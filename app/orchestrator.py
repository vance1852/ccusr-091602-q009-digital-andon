"""数字安灯事件编排核心。

职责：
- 把原始告警按关联组 + 时间窗归并成有边界的生产事件，原始信号全部保留；
- 抖动期抑制重复通知，严重度升级立即放行；
- 恢复信号只清除自己的证据，绝不单方面关闭仍有其他证据支撑的事件；
- 剧本步骤带前置条件 / 超时 / 补偿，自动步骤只在安全许可有效时执行；
- 人工接管后，后续自动回调仅留痕，不能夺回控制权；
- 值守员操作（确认 / 转派 / 暂停 / 结案等）全部留班组与理由。
"""
from __future__ import annotations

import itertools
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import load_alarm_map, load_playbooks, load_topology
from .models import (
    AuditEntry,
    CallbackResult,
    ControlOwner,
    Evidence,
    Incident,
    IncidentState,
    Notification,
    Permit,
    PlaybookInstance,
    Severity,
    Signal,
    SignalKind,
    StepInstance,
    StepState,
)


class OrchestrationError(Exception):
    """违反编排约束（未知告警码、证据未清却结案、缺少理由等）。"""


def _parse_time(value) -> float:
    """接受 epoch 秒或 ISO-8601 字符串，统一为 epoch 秒。"""
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


class NotificationCenter:
    """通知策略：抖动抑制、升级必达、全部留痕（含被抑制的记录）。"""

    SUPPRESSIBLE = frozenset({"opened", "reopened", "evidence", "recovered"})

    def __init__(self, window_seconds: float):
        self.window_seconds = float(window_seconds)
        self.history: list = []
        self._last_bucket_sent_at: dict = {}
        self._max_sent_severity: dict = {}
        self._seq = itertools.count(1)

    def notify(self, incident_id: str, kind: str, severity: Severity, at: float, message: str) -> Notification:
        prev_max = self._max_sent_severity.get(incident_id)
        escalates = prev_max is not None and severity > prev_max
        # 升级（严重度超过已通知过的最高级别）必须立即显现，不受抑制窗口约束。
        if kind in self.SUPPRESSIBLE and not escalates:
            last = self._last_bucket_sent_at.get(incident_id)
            if last is not None and at - last < self.window_seconds:
                note = Notification(
                    id=f"ntf-{next(self._seq):05d}",
                    incident_id=incident_id,
                    kind=kind,
                    severity=severity,
                    at=at,
                    status="suppressed",
                    message=message,
                    reason="duplicate_within_window",
                )
                self.history.append(note)
                return note
        note = Notification(
            id=f"ntf-{next(self._seq):05d}",
            incident_id=incident_id,
            kind=kind,
            severity=severity,
            at=at,
            status="sent",
            message=message,
        )
        self.history.append(note)
        # 只有可抑制类通知（以及升级）才占用抑制窗口；
        # step_failed / permit_revoked 等运维通知不应压制后续的 recovered。
        if kind in self.SUPPRESSIBLE or kind == "escalated":
            self._last_bucket_sent_at[incident_id] = at
        if prev_max is None or severity > prev_max:
            self._max_sent_severity[incident_id] = severity
        return note

    def for_incident(self, incident_id: str) -> list:
        return [n for n in self.history if n.incident_id == incident_id]


class PermitRegistry:
    """安全许可登记处：按作用域（单元）签发、撤销、判定有效性。"""

    def __init__(self):
        self._permits: dict = {}

    def grant(self, permit_id: str, scope: str, granted_by: str, valid_from, valid_to) -> Permit:
        if permit_id in self._permits:
            raise OrchestrationError(f"许可编号重复: {permit_id}")
        permit = Permit(
            permit_id=permit_id,
            scope=scope,
            granted_by=granted_by,
            valid_from=_parse_time(valid_from),
            valid_to=_parse_time(valid_to),
        )
        self._permits[permit_id] = permit
        return permit

    def revoke(self, permit_id: str, reason: str) -> Permit:
        permit = self._permits.get(permit_id)
        if permit is None:
            raise OrchestrationError(f"未知许可: {permit_id}")
        permit.revoked = True
        permit.revoke_reason = reason
        return permit

    def get(self, permit_id: str) -> Permit:
        permit = self._permits.get(permit_id)
        if permit is None:
            raise OrchestrationError(f"未知许可: {permit_id}")
        return permit

    def valid(self, scope: Optional[str], now: float) -> bool:
        if scope is None:
            return True
        return any(p.scope == scope and p.valid(now) for p in self._permits.values())


class Orchestrator:
    """编排门面：信号接入、剧本推进、值守员操作与查询视图。"""

    def __init__(
        self,
        *,
        topology,
        alarm_map,
        playbooks,
        clock=None,
        suppression_window: float = 60.0,
        correlation_window: float = 300.0,
    ):
        self.topology = topology
        self.alarm_map = alarm_map
        self.playbook_defs = playbooks
        self._clock = clock or time.time
        self.correlation_window = float(correlation_window)
        self.notifications = NotificationCenter(suppression_window)
        self.permits = PermitRegistry()
        self._signals: dict = {}
        self._incidents: dict = {}
        self._audit_log: list = []
        self._seq = itertools.count(1)

    @classmethod
    def from_config_dir(cls, config_dir=None, **kwargs) -> "Orchestrator":
        base = Path(config_dir) if config_dir else Path(__file__).resolve().parent.parent / "config"
        topology = load_topology(base / "topology.json")
        alarm_map = load_alarm_map(base / "alarm_map.json", topology)
        playbooks = load_playbooks(base / "playbooks.json")
        return cls(topology=topology, alarm_map=alarm_map, playbooks=playbooks, **kwargs)

    # ------------------------------------------------------------------
    # 基础工具
    # ------------------------------------------------------------------

    def _now(self) -> float:
        return float(self._clock())

    def _next_id(self, prefix: str) -> str:
        return f"{prefix}-{next(self._seq):05d}"

    def _audit(self, incident_id, actor, shift, event, reason=None, **details) -> AuditEntry:
        entry = AuditEntry(
            id=self._next_id("aud"),
            at=self._now(),
            incident_id=incident_id,
            actor=actor,
            shift=shift,
            action=event,
            reason=reason,
            details=details,
        )
        self._audit_log.append(entry)
        return entry

    @staticmethod
    def _require_reason(reason) -> None:
        if not reason or not str(reason).strip():
            raise OrchestrationError("该操作必须填写理由")

    def get_incident(self, incident_id: str) -> Incident:
        inc = self._incidents.get(incident_id)
        if inc is None:
            raise OrchestrationError(f"未知事件: {incident_id}")
        return inc

    def _require_open(self, incident_id: str) -> Incident:
        inc = self.get_incident(incident_id)
        if inc.state == IncidentState.CLOSED:
            raise OrchestrationError(f"事件已结案: {incident_id}")
        return inc

    # ------------------------------------------------------------------
    # 信号接入
    # ------------------------------------------------------------------

    def ingest(self, alarm_code: str, occurred_at=None, payload=None) -> Signal:
        """接入一条原始告警。信号永远落库，随后按规则归并。"""
        now = self._now()
        mapping = self.alarm_map.get(alarm_code)
        if mapping is None:
            raise OrchestrationError(f"未映射的告警码: {alarm_code}")
        device = self.topology.devices[mapping.device]
        ts = _parse_time(occurred_at) if occurred_at is not None else now
        sig = Signal(
            id=self._next_id("sig"),
            alarm_code=alarm_code,
            device=mapping.device,
            unit=device.unit,
            kind=mapping.kind,
            severity=mapping.severity,
            incident_type=mapping.incident_type,
            correlation_group=mapping.correlation_group,
            role=mapping.role,
            occurred_at=ts,
            received_at=now,
            evidence_key=mapping.evidence_key,
            payload=dict(payload or {}),
        )
        self._signals[sig.id] = sig
        if sig.kind is SignalKind.FAULT:
            self._ingest_fault(sig, now)
        else:
            self._ingest_recovery(sig, now)
        return sig

    def _ingest_fault(self, sig: Signal, now: float) -> None:
        inc = self._find_correlated_incident(sig)
        created = inc is None
        if created:
            inc = self._new_incident(sig, now)
        prev = self._active_severity(inc)
        inc.signal_ids.append(sig.id)
        inc.last_signal_at = max(inc.last_signal_at, sig.occurred_at)
        inc.evidence[sig.evidence_key] = Evidence(
            key=sig.evidence_key,
            device=sig.device,
            unit=sig.unit,
            alarm_code=sig.alarm_code,
            severity=sig.severity,
            role=sig.role,
            opened_at=sig.occurred_at,
            signal_id=sig.id,
        )
        inc.severity = self._active_severity(inc) or inc.severity
        inc.max_severity = max(inc.max_severity, sig.severity)
        if created:
            self.notifications.notify(
                inc.id, "opened", sig.severity, now,
                f"事件 {inc.id} 建立：{sig.alarm_code} @ {sig.device}",
            )
            self._maybe_start_playbook(inc, now)
        else:
            if inc.state == IncidentState.MONITORING:
                inc.state = IncidentState.OPEN
                self.notifications.notify(
                    inc.id, "reopened", sig.severity, now,
                    f"事件 {inc.id} 出现新故障信号，重新打开",
                )
            if prev is not None and sig.severity > prev:
                # 严重度升级：立即通知，跳过抑制窗口。
                self.notifications.notify(
                    inc.id, "escalated", sig.severity, now,
                    f"事件 {inc.id} 严重度升级为 {sig.severity.label}",
                )
            else:
                self.notifications.notify(
                    inc.id, "evidence", sig.severity, now,
                    f"事件 {inc.id} 新增证据 {sig.alarm_code} @ {sig.device}",
                )
        self._advance(inc, now)

    def _ingest_recovery(self, sig: Signal, now: float) -> None:
        inc = self._find_incident_holding(sig)
        if inc is not None:
            inc.signal_ids.append(sig.id)
            inc.last_signal_at = max(inc.last_signal_at, sig.occurred_at)
            inc.evidence.pop(sig.evidence_key, None)
            self._audit(inc.id, "automation", None, "evidence_cleared", None,
                        key=sig.evidence_key, device=sig.device)
            inc.severity = self._active_severity(inc) or inc.severity
            if not inc.evidence and inc.state in (
                IncidentState.OPEN,
                IncidentState.ACKNOWLEDGED,
                IncidentState.MITIGATING,
            ):
                # 所有证据都已清除：转入观察，而不是直接结案（结案只能由值守员执行）。
                inc.state = IncidentState.MONITORING
                self.notifications.notify(
                    inc.id, "recovered", Severity.INFO, now,
                    f"事件 {inc.id} 证据全部清除，转入观察",
                )
            self._advance(inc, now)
            return
        # 晚到或重复的恢复信号：没有匹配的活跃证据，只留痕，绝不改变事件状态。
        target = self._most_recent_incident(sig.correlation_group)
        if target is not None:
            target.signal_ids.append(sig.id)
            target.last_signal_at = max(target.last_signal_at, sig.occurred_at)
        self._audit(
            target.id if target else None, "automation", None, "late_recovery",
            "恢复信号没有匹配的活跃证据，仅留痕",
            device=sig.device, alarm_code=sig.alarm_code,
        )

    def _new_incident(self, sig: Signal, now: float) -> Incident:
        inc = Incident(
            id=self._next_id("inc"),
            incident_type=sig.incident_type,
            correlation_group=sig.correlation_group,
            created_at=now,
            topology_version=self.topology.version,
            last_signal_at=sig.occurred_at,
        )
        self._incidents[inc.id] = inc
        self._audit(inc.id, "automation", None, "incident_created", None,
                    alarm_code=sig.alarm_code, device=sig.device)
        return inc

    def _find_correlated_incident(self, sig: Signal) -> Optional[Incident]:
        candidates = [
            inc for inc in self._incidents.values()
            if inc.correlation_group == sig.correlation_group
            and inc.state != IncidentState.CLOSED
            and inc.merged_into is None
            and abs(sig.occurred_at - inc.last_signal_at) <= self.correlation_window
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda i: i.last_signal_at)

    def _find_incident_holding(self, sig: Signal) -> Optional[Incident]:
        holders = [
            inc for inc in self._incidents.values()
            if inc.state != IncidentState.CLOSED and sig.evidence_key in inc.evidence
        ]
        if not holders:
            return None
        same_group = [i for i in holders if i.correlation_group == sig.correlation_group]
        return max(same_group or holders, key=lambda i: i.last_signal_at)

    def _most_recent_incident(self, correlation_group: str) -> Optional[Incident]:
        pool = [i for i in self._incidents.values() if i.correlation_group == correlation_group]
        if not pool:
            pool = list(self._incidents.values())
        if not pool:
            return None
        return max(pool, key=lambda i: i.last_signal_at)

    @staticmethod
    def _active_severity(inc: Incident) -> Optional[Severity]:
        if not inc.evidence:
            return None
        return max(ev.severity for ev in inc.evidence.values())

    # ------------------------------------------------------------------
    # 剧本引擎
    # ------------------------------------------------------------------

    def _maybe_start_playbook(self, inc: Incident, now: float) -> None:
        defn = self.playbook_defs.get(inc.incident_type)
        if defn is None:
            return
        if inc.playbook is not None and inc.playbook.status == "active":
            return
        inc.playbook = PlaybookInstance(
            id=self._next_id("pbk"),
            playbook_id=defn.playbook_id,
            incident_id=inc.id,
            permit_scope=defn.permit_scope,
            started_at=now,
            steps=[
                StepInstance(
                    step_id=s.step_id,
                    name=s.name,
                    kind=s.kind,
                    action=s.action,
                    requires_permit=s.requires_permit,
                    timeout_seconds=s.timeout_seconds,
                    preconditions=s.preconditions,
                    compensation=s.compensation,
                )
                for s in defn.steps
            ],
        )
        if inc.state in (IncidentState.OPEN, IncidentState.ACKNOWLEDGED):
            inc.state = IncidentState.MITIGATING
        self._audit(inc.id, "automation", None, "playbook_started", None,
                    playbook=defn.playbook_id)

    def _advance(self, inc: Incident, now: float) -> None:
        pb = inc.playbook
        if pb is None or pb.status != "active":
            return
        if inc.paused or inc.state == IncidentState.CLOSED:
            return
        for _ in range(len(pb.steps) + 2):
            step = next((s for s in pb.steps if s.state != StepState.COMPLETED), None)
            if step is None:
                pb.status = "completed"
                self._audit(inc.id, "automation", None, "playbook_completed", None,
                            playbook=pb.playbook_id)
                return
            if step.state == StepState.FAILED:
                pb.status = "halted"
                return
            if step.state == StepState.COMPENSATING:
                if self._try_compensate(inc, pb, step, now):
                    continue
                return
            if step.state == StepState.PENDING:
                if not self._start_step(inc, pb, step, now):
                    return
                continue
            # RUNNING / WAITING
            if step.held:
                return
            if (
                step.timeout_seconds is not None
                and step.started_at is not None
                and now - step.started_at > step.timeout_seconds
            ):
                self._fail_step(inc, pb, step, "timeout", now)
                continue
            return

    def _start_step(self, inc: Incident, pb: PlaybookInstance, step: StepInstance, now: float) -> bool:
        reasons = []
        if step.kind == "automatic" and inc.control_owner != ControlOwner.AUTOMATION:
            reasons.append("control_not_automation")
        unmet = [p for p in step.preconditions if not self._precondition_met(inc, p)]
        if unmet:
            reasons.append("precondition_unmet:" + ",".join(unmet))
        if step.requires_permit and not self.permits.valid(pb.permit_scope, now):
            reasons.append("permit_invalid")
        if reasons:
            step.blocked_reason = ";".join(reasons)
            return False
        step.blocked_reason = None
        step.started_at = now
        if step.kind == "automatic":
            step.state = StepState.RUNNING
            if step.execution_id is not None:
                # 旧执行实例退役：其后的迟到回调可识别为 stale 而非 unknown。
                step.retired_execution_ids.append(step.execution_id)
            step.execution_id = self._next_id("exe")
            self._audit(inc.id, "automation", None, "action_dispatched", None,
                        step=step.step_id, action=step.action,
                        execution_id=step.execution_id)
        else:
            step.state = StepState.WAITING
            self._audit(inc.id, "automation", None, "manual_step_requested", None,
                        step=step.step_id)
        return True

    def _precondition_met(self, inc: Incident, expr: str) -> bool:
        if expr == "evidence_clear":
            return not inc.evidence
        if expr.startswith("state:"):
            return inc.state.value == expr.split(":", 1)[1]
        if expr.startswith("permit:"):
            return self.permits.valid(expr.split(":", 1)[1], self._now())
        return False

    def _fail_step(self, inc: Incident, pb: PlaybookInstance, step: StepInstance, reason: str, now: float) -> None:
        step.failure_reason = reason
        self._audit(inc.id, "automation", None, "step_failed", reason, step=step.step_id)
        self.notifications.notify(
            inc.id, "step_failed", inc.max_severity, now,
            f"事件 {inc.id} 步骤 {step.step_id} 失败：{reason}",
        )
        if step.compensation:
            step.state = StepState.COMPENSATING
            self._try_compensate(inc, pb, step, now)
        else:
            step.state = StepState.FAILED

    def _try_compensate(self, inc: Incident, pb: PlaybookInstance, step: StepInstance, now: float) -> bool:
        comp = step.compensation or {}
        if comp.get("requires_permit") and not self.permits.valid(pb.permit_scope, now):
            # 补偿本身需要许可而许可无效：挂起，步骤停留在 compensating（卡住的步骤）。
            return False
        step.compensation_record = {"action": comp.get("action"), "at": now, "status": "executed"}
        self._audit(inc.id, "automation", None, "compensation_executed", step.failure_reason,
                    step=step.step_id, action=comp.get("action"))
        step.state = StepState.FAILED
        return True

    def tick(self) -> None:
        """推进所有未结案事件的剧本（超时检查、补偿重试、解除阻塞）。"""
        now = self._now()
        for inc in self._incidents.values():
            self._advance(inc, now)

    # ------------------------------------------------------------------
    # 自动化回调：必须携带执行实例与步骤标识
    # ------------------------------------------------------------------

    def step_callback(self, execution_id: str, step_id: str, succeeded: bool = True, detail=None) -> CallbackResult:
        now = self._now()
        located = self._locate_execution(execution_id)
        if located is None:
            self._audit(None, "automation", None, "ignored_callback", "unknown_execution",
                        execution_id=execution_id, step_id=step_id)
            return CallbackResult(False, "unknown_execution")
        inc, pb, step = located
        reason = None
        if step.step_id != step_id:
            reason = "step_mismatch"
        elif inc.control_owner != ControlOwner.AUTOMATION:
            # 人工接管后：自动回调仅留痕，不能夺回控制权。
            reason = "manual_control"
        elif inc.paused:
            reason = "paused"
        elif step.held:
            reason = "held"
        elif step.state != StepState.RUNNING or step.execution_id != execution_id:
            reason = "stale_execution"
        if reason is not None:
            self._audit(inc.id, "automation", None, "ignored_callback", reason,
                        execution_id=execution_id, step_id=step_id)
            return CallbackResult(False, reason)
        if succeeded:
            step.state = StepState.COMPLETED
            step.completed_at = now
            self._audit(inc.id, "automation", None, "step_completed", None,
                        step=step.step_id, execution_id=execution_id, detail=detail)
        else:
            self._fail_step(inc, pb, step, f"callback_failure:{detail}", now)
        self._advance(inc, now)
        return CallbackResult(True, "accepted")

    def _locate_execution(self, execution_id: str):
        for inc in self._incidents.values():
            pb = inc.playbook
            if pb is None:
                continue
            for step in pb.steps:
                if step.execution_id == execution_id or execution_id in step.retired_execution_ids:
                    return inc, pb, step
        return None

    # ------------------------------------------------------------------
    # 安全许可
    # ------------------------------------------------------------------

    def grant_permit(self, permit_id: str, scope: str, granted_by: str, valid_from, valid_to) -> Permit:
        permit = self.permits.grant(permit_id, scope, granted_by, valid_from, valid_to)
        self._audit(None, granted_by, None, "permit_granted", None,
                    scope=scope, permit_id=permit_id)
        now = self._now()
        for inc in self._incidents.values():
            pb = inc.playbook
            if pb is not None and pb.status == "active" and pb.permit_scope == scope:
                self._advance(inc, now)
        return permit

    def revoke_permit(self, permit_id: str, reason: str) -> Permit:
        self._require_reason(reason)
        permit = self.permits.revoke(permit_id, reason)
        now = self._now()
        self._audit(None, "safety", None, "permit_revoked", reason,
                    scope=permit.scope, permit_id=permit_id)
        for inc in self._incidents.values():
            pb = inc.playbook
            if inc.state == IncidentState.CLOSED or pb is None or pb.status != "active":
                continue
            if pb.permit_scope != permit.scope:
                continue
            self.notifications.notify(
                inc.id, "permit_revoked", inc.max_severity, now,
                f"安全许可 {permit_id} 已撤销，相关自动步骤停止",
            )
            for step in pb.steps:
                if step.kind != "automatic" or not step.requires_permit:
                    continue
                if step.state == StepState.RUNNING:
                    self._fail_step(inc, pb, step, "permit_revoked", now)
                elif step.state == StepState.PENDING:
                    step.blocked_reason = "permit_invalid"
            self._advance(inc, now)
        return permit

    # ------------------------------------------------------------------
    # 值守员操作（全部留班组与理由）
    # ------------------------------------------------------------------

    def acknowledge(self, incident_id: str, operator: str, shift: str, reason: str) -> AuditEntry:
        inc = self._require_open(incident_id)
        self._require_reason(reason)
        if inc.state != IncidentState.CLOSED:
            inc.state = IncidentState.ACKNOWLEDGED
        return self._audit(inc.id, operator, shift, "acknowledged", reason)

    def reassign(self, incident_id: str, target: str, operator: str, shift: str, reason: str) -> AuditEntry:
        inc = self._require_open(incident_id)
        self._require_reason(reason)
        inc.assigned_to = target
        return self._audit(inc.id, operator, shift, "reassigned", reason, target=target)

    def pause(self, incident_id: str, operator: str, shift: str, reason: str) -> AuditEntry:
        inc = self._require_open(incident_id)
        self._require_reason(reason)
        inc.paused = True
        return self._audit(inc.id, operator, shift, "paused", reason)

    def resume(self, incident_id: str, operator: str, shift: str, reason: str) -> AuditEntry:
        inc = self._require_open(incident_id)
        self._require_reason(reason)
        inc.paused = False
        entry = self._audit(inc.id, operator, shift, "resumed", reason)
        self._advance(inc, self._now())
        return entry

    def take_control(self, incident_id: str, operator: str, shift: str, reason: str) -> AuditEntry:
        """人工接管：挂起运行中的自动步骤；此后自动回调仅留痕。"""
        inc = self._require_open(incident_id)
        self._require_reason(reason)
        inc.control_owner = ControlOwner.OPERATOR
        held = []
        pb = inc.playbook
        if pb is not None and pb.status == "active":
            for step in pb.steps:
                if step.state == StepState.RUNNING and step.kind == "automatic":
                    step.held = True
                    step.state = StepState.WAITING
                    held.append(step.step_id)
                    self._audit(inc.id, operator, shift, "step_held",
                                "人工接管，自动步骤挂起",
                                step=step.step_id, execution_id=step.execution_id)
        entry = self._audit(inc.id, operator, shift, "take_control", reason, held_steps=held)
        self.notifications.notify(
            inc.id, "control_changed", inc.max_severity, self._now(),
            f"事件 {inc.id} 控制权移交值守员 {operator}",
        )
        return entry

    def delegate_control(self, incident_id: str, target: str, operator: str, shift: str, reason: str) -> AuditEntry:
        """值守员 / 安全员显式交还控制权；自动化自己不能夺回。"""
        inc = self._require_open(incident_id)
        self._require_reason(reason)
        owner = ControlOwner(target)
        inc.control_owner = owner
        pb = inc.playbook
        if pb is not None and pb.status == "active" and owner == ControlOwner.AUTOMATION:
            for step in pb.steps:
                if step.held:
                    # 重新评估：旧执行实例作废，重启时会分配新的执行标识。
                    step.held = False
                    step.state = StepState.PENDING
                    step.started_at = None
        entry = self._audit(inc.id, operator, shift, "delegate_control", reason, target=owner.value)
        self.notifications.notify(
            inc.id, "control_changed", inc.max_severity, self._now(),
            f"事件 {inc.id} 控制权移交 {owner.value}",
        )
        self._advance(inc, self._now())
        return entry

    def complete_manual_step(self, incident_id: str, step_id: str, operator: str, shift: str, reason: str) -> AuditEntry:
        inc = self._require_open(incident_id)
        self._require_reason(reason)
        pb = inc.playbook
        if pb is None or pb.status != "active":
            raise OrchestrationError("事件没有进行中的剧本")
        step = next((s for s in pb.steps if s.step_id == step_id), None)
        if step is None:
            raise OrchestrationError(f"未知步骤: {step_id}")
        if step.kind != "manual":
            raise OrchestrationError(f"步骤 {step_id} 不是人工步骤")
        if step.state != StepState.WAITING:
            raise OrchestrationError(f"步骤 {step_id} 当前状态不允许人工完成: {step.state.value}")
        step.state = StepState.COMPLETED
        step.completed_at = self._now()
        step.held = False
        entry = self._audit(inc.id, operator, shift, "manual_step_completed", reason, step=step_id)
        self._advance(inc, self._now())
        return entry

    def close(self, incident_id: str, operator: str, shift: str, reason: str, force: bool = False) -> AuditEntry:
        inc = self._require_open(incident_id)
        self._require_reason(reason)
        if inc.evidence and not force:
            raise OrchestrationError("事件仍有活跃证据，不能结案（确需结案请 force=True 并记录理由）")
        inc.state = IncidentState.CLOSED
        if inc.playbook is not None and inc.playbook.status == "active":
            inc.playbook.status = "closed"
        entry = self._audit(inc.id, operator, shift, "closed", reason,
                            force=force, remaining_evidence=sorted(inc.evidence))
        self.notifications.notify(
            inc.id, "closed", inc.max_severity, self._now(),
            f"事件 {inc.id} 由 {operator} 结案",
        )
        return entry

    def link_incidents(self, primary_id: str, secondary_id: str, operator: str, shift: str, reason: str) -> AuditEntry:
        """把 secondary 关联合并到 primary；两者各自信号与留痕仍可分别追溯。"""
        primary = self._require_open(primary_id)
        secondary = self.get_incident(secondary_id)
        if primary.id == secondary.id:
            raise OrchestrationError("不能把事件合并到自身")
        if secondary.merged_into is not None:
            raise OrchestrationError(f"事件 {secondary_id} 已合并到 {secondary.merged_into}")
        self._require_reason(reason)
        secondary.merged_into = primary.id
        primary.linked_children.append(secondary.id)
        self._audit(secondary.id, operator, shift, "merged_into_primary", reason, primary=primary.id)
        entry = self._audit(primary.id, operator, shift, "incident_linked", reason, secondary=secondary.id)
        self.notifications.notify(
            primary.id, "merged", primary.max_severity, self._now(),
            f"事件 {secondary.id} 已关联合并到 {primary.id}",
        )
        return entry

    # ------------------------------------------------------------------
    # 查询视图
    # ------------------------------------------------------------------

    def list_incidents(self) -> list:
        return [
            {
                "id": inc.id,
                "type": inc.incident_type,
                "state": inc.state.value,
                "severity": inc.severity.label,
                "control_owner": inc.control_owner.value,
                "created_at": inc.created_at,
                "signal_count": len(inc.signal_ids),
                "merged_into": inc.merged_into,
            }
            for inc in self._incidents.values()
        ]

    def notification_history(self, incident_id: Optional[str] = None) -> list:
        if incident_id is None:
            return list(self.notifications.history)
        return self.notifications.for_incident(incident_id)

    def audit_trail(self, incident_id: Optional[str] = None) -> list:
        if incident_id is None:
            return list(self._audit_log)
        return [a for a in self._audit_log if a.incident_id == incident_id]

    def operations_view(self, incident_id: str) -> dict:
        """值守视图：根因候选、受影响单元、控制权、卡住的步骤、通知历史。"""
        inc = self.get_incident(incident_id)
        now = self._now()
        signals = [self._signals[sid] for sid in inc.signal_ids]
        return {
            "id": inc.id,
            "type": inc.incident_type,
            "state": inc.state.value,
            "severity": inc.severity.label,
            "max_severity": inc.max_severity.label,
            "control_owner": inc.control_owner.value,
            "paused": inc.paused,
            "assigned_to": inc.assigned_to,
            "topology_version": inc.topology_version,
            "created_at": inc.created_at,
            "root_cause_candidates": self._root_cause_candidates(inc, signals),
            "affected_units": self._affected_units(inc, signals),
            "active_evidence": [
                {
                    "key": ev.key,
                    "device": ev.device,
                    "unit": ev.unit,
                    "alarm_code": ev.alarm_code,
                    "severity": ev.severity.label,
                    "opened_at": ev.opened_at,
                }
                for ev in inc.evidence.values()
            ],
            "playbook": self._playbook_view(inc),
            "stuck_steps": self._stuck_steps(inc, now),
            "notifications": [self._notification_view(n) for n in self.notifications.for_incident(inc.id)],
            "signals": [self._signal_view(s) for s in signals],
            "signal_count": len(signals),
            "audit": [self._audit_view(a) for a in self.audit_trail(inc.id)],
            "merged_into": inc.merged_into,
            "linked_children": list(inc.linked_children),
        }

    def _root_cause_candidates(self, inc: Incident, signals: list) -> list:
        faults = [s for s in signals if s.kind is SignalKind.FAULT]
        by_device: dict = {}
        for s in faults:
            by_device.setdefault(s.device, []).append(s)
        candidates = []
        for dev, dev_signals in by_device.items():
            descendants = sorted({
                s.device for s in faults
                if s.device != dev and self.topology.is_ancestor(dev, s.device)
            })
            root_signals = [s for s in dev_signals if s.role == "root"]
            score = 2 * len(descendants) + (1 if root_signals else 0)
            rationale = []
            if descendants:
                rationale.append(f"位于 {len(descendants)} 个告警设备的上游：{', '.join(descendants)}")
            if root_signals:
                rationale.append("设备自身上报根因类告警")
            if not rationale:
                rationale.append("仅表现为下游症状")
            candidates.append({
                "device": dev,
                "unit": self.topology.devices[dev].unit,
                "score": score,
                "active": any(ev.device == dev for ev in inc.evidence.values()),
                "first_signal_at": min(s.occurred_at for s in dev_signals),
                "rationale": "；".join(rationale),
            })
        candidates.sort(key=lambda c: (-c["score"], c["first_signal_at"]))
        return candidates

    def _affected_units(self, inc: Incident, signals: list) -> list:
        units: dict = {}
        for s in signals:
            entry = units.setdefault(s.unit, {"unit": s.unit, "devices": set(), "active": False})
            entry["devices"].add(s.device)
        for ev in inc.evidence.values():
            if ev.unit in units:
                units[ev.unit]["active"] = True
        return [
            {"unit": u["unit"], "devices": sorted(u["devices"]), "active": u["active"]}
            for u in sorted(units.values(), key=lambda x: x["unit"])
        ]

    def _playbook_view(self, inc: Incident) -> Optional[dict]:
        pb = inc.playbook
        if pb is None:
            return None
        return {
            "id": pb.id,
            "playbook_id": pb.playbook_id,
            "status": pb.status,
            "permit_scope": pb.permit_scope,
            "steps": [
                {
                    "step_id": s.step_id,
                    "name": s.name,
                    "kind": s.kind,
                    "state": s.state.value,
                    "blocked_reason": s.blocked_reason,
                    "failure_reason": s.failure_reason,
                    "execution_id": s.execution_id,
                    "started_at": s.started_at,
                    "held": s.held,
                    "compensation": s.compensation_record,
                }
                for s in pb.steps
            ],
        }

    def _stuck_steps(self, inc: Incident, now: float) -> list:
        pb = inc.playbook
        if pb is None:
            return []
        stuck = []
        for s in pb.steps:
            reason = None
            if s.state == StepState.FAILED:
                reason = s.failure_reason or "failed"
            elif s.state == StepState.COMPENSATING:
                reason = "compensation_deferred"
            elif s.state == StepState.PENDING and s.blocked_reason:
                reason = s.blocked_reason
            elif s.held:
                reason = "held_by_operator"
            elif (
                s.state in (StepState.RUNNING, StepState.WAITING)
                and s.timeout_seconds is not None
                and s.started_at is not None
                and now - s.started_at > s.timeout_seconds
            ):
                reason = "timeout"
            if reason:
                stuck.append({
                    "step_id": s.step_id,
                    "name": s.name,
                    "state": s.state.value,
                    "reason": reason,
                })
        return stuck

    @staticmethod
    def _signal_view(s: Signal) -> dict:
        return {
            "id": s.id,
            "alarm_code": s.alarm_code,
            "device": s.device,
            "unit": s.unit,
            "kind": s.kind.value,
            "severity": s.severity.label,
            "occurred_at": s.occurred_at,
            "received_at": s.received_at,
            "evidence_key": s.evidence_key,
        }

    @staticmethod
    def _notification_view(n: Notification) -> dict:
        return {
            "id": n.id,
            "kind": n.kind,
            "severity": n.severity.label,
            "at": n.at,
            "status": n.status,
            "reason": n.reason,
            "message": n.message,
        }

    @staticmethod
    def _audit_view(a: AuditEntry) -> dict:
        return {
            "id": a.id,
            "at": a.at,
            "actor": a.actor,
            "shift": a.shift,
            "action": a.action,
            "reason": a.reason,
            "details": a.details,
        }

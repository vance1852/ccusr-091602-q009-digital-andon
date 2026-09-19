"""数字安灯编排引擎。

把各子系统粘合成一个判定内核：

ingest(原始信号) -> 台账留存 -> 告警映射规范化 -> 事件归并/证据生命周期
-> 通知（抖动抑制 / 升级穿透）-> 剧本推进（前置条件 + 安全许可 + 超时补偿）。

所有时间戳由调用方提供（毫秒），引擎不依赖墙钟，便于回灌历史信号与测试。
"""
from __future__ import annotations

from typing import Any, Callable, Mapping, Sequence

from .alarms import AlarmDef, AlarmMap, correlation_values
from .gateway import CommandGateway
from .incidents import Incident
from .model import (
    OWNER_AUTOMATION,
    OWNER_OPERATOR,
    OWNER_SAFETY,
    SIGNAL_CLEAR,
    SIGNAL_INFO,
    SIGNAL_RAISE,
    STEP_COMPENSATING,
    STEP_PENDING,
    STEP_RUNNING,
    STEP_WAITING,
    AuditEvent,
    Severity,
    Signal,
    severity_value,
)
from .notifications import NotificationLog, SignalLedger
from .playbooks import (
    MODE_AUTO,
    MODE_MANUAL,
    ON_TIMEOUT_COMPENSATE,
    PlaybookInstance,
    PlaybookLibrary,
    StepDef,
)
from .safety import SafetyRegistry
from .topology import Topology, downstream, impacted_units

Precondition = Callable[..., tuple[bool, str]]


class EngineContext:
    """传给前置条件谓词的只读上下文。"""

    def __init__(self, engine: "OrchestrationEngine"):
        self.engine = engine

    @property
    def now(self) -> int:
        return self.engine.now


class CallbackVerdict:
    IGNORED = "ignored"          # 未知/重复/结案后到达
    SHADOW = "shadow"            # 人工接管后到达，仅留痕
    APPLIED = "applied"          # 正常驱动剧本状态


class OrchestrationEngine:
    def __init__(
        self,
        topology: Topology,
        alarm_map: AlarmMap,
        playbooks: PlaybookLibrary,
        safety: SafetyRegistry | None = None,
        *,
        auto_close_grace_ms: int = 30_000,
    ):
        self.topo = topology
        self.alarm_map = alarm_map
        self.playbooks = playbooks
        self.safety = safety or SafetyRegistry()
        self.gateway = CommandGateway()
        self.ledger = SignalLedger()
        self.notifications = NotificationLog()
        self.incidents: dict[str, Incident] = {}
        self.runs: dict[str, PlaybookInstance] = {}
        self.audits: list[AuditEvent] = []
        self.now = -1
        self.auto_close_grace_ms = auto_close_grace_ms
        self._monitoring_deadline: dict[str, int] = {}
        self._signal_seq = 0
        self._audit_seq = 0
        self._inc_seq = 0
        self._dispatch_seq = 0
        self._preconditions: dict[str, Precondition] = {}
        self._register_default_preconditions()

    # ================================================================
    # 前置条件
    # ================================================================
    def register_precondition(self, name: str, fn: Precondition) -> None:
        self._preconditions[name] = fn

    def _register_default_preconditions(self) -> None:
        def fault_active(ctx, inc, run, step, ts):
            if inc.active_evidence:
                return True, ""
            return False, "故障证据已全部恢复，不应执行该动作"

        def fault_cleared(ctx, inc, run, step, ts):
            if not inc.active_evidence:
                return True, ""
            return False, f"仍有活动证据: {inc.close_blockers()}"

        def acknowledged(ctx, inc, run, step, ts):
            if inc.acknowledged_ts is not None:
                return True, ""
            return False, "事件尚未经值守员确认"

        def no_interlock(ctx, inc, run, step, ts):
            active = [i.reason for i in self.safety.active_interlocks()]
            if not active:
                return True, ""
            return False, f"存在活动联锁: {active}"

        self.register_precondition("fault_active", fault_active)
        self.register_precondition("fault_cleared", fault_cleared)
        self.register_precondition("acknowledged", acknowledged)
        self.register_precondition("no_interlock", no_interlock)

    # ================================================================
    # 审计
    # ================================================================
    def _audit(self, ts: int, action: str, reason: str,
               actor: str = "orchestrator", team: str = "automation",
               detail: Mapping[str, Any] | None = None) -> AuditEvent:
        self._audit_seq += 1
        ev = AuditEvent(
            seq=self._audit_seq, ts=ts, actor=actor, team=team,
            action=action, reason=reason, detail=dict(detail or {}),
        )
        self.audits.append(ev)
        return ev

    # ================================================================
    # 信号接入
    # ================================================================
    def ingest_many(self, raws: Sequence[Mapping[str, Any]]) -> list[Incident]:
        touched: dict[str, Incident] = {}
        for raw in raws:
            inc = self.ingest(raw)
            if inc is not None:
                touched[inc.id] = inc
        return list(touched.values())

    def ingest(self, raw: Mapping[str, Any]) -> Incident | None:
        ts = int(raw["ts"])
        self.now = max(self.now, ts)
        device_id = str(raw["device"])
        code = str(raw["code"])
        d = self.alarm_map.require(code)
        kind = str(raw.get("kind") or self._infer_kind(d))
        payload = dict(raw.get("payload", {}))
        if raw.get("severity") is not None:
            sev = severity_value(raw["severity"])
        elif kind == SIGNAL_RAISE:
            sev = d.default_severity
        else:
            sev = None
        self._signal_seq += 1
        correlation = frozenset(correlation_values(d, payload))
        fingerprint = f"{device_id}|{code}|" + "&".join(
            f"{k}={v}" for k, v in sorted(correlation))
        sig = Signal(
            seq=self._signal_seq, ts=ts, device_id=device_id, code=code,
            kind=kind, severity=sev, fingerprint=fingerprint,
            payload=payload, raw=str(raw.get("raw", "")),
        )
        rec = self.ledger.append(sig)
        topo = self.topo.version_at(ts)
        device = topo.devices.get(device_id)
        unit = device.unit if device else None

        if kind == SIGNAL_RAISE:
            inc = self._handle_raise(sig, d, correlation, fingerprint, unit)
        elif kind == SIGNAL_CLEAR:
            inc = self._handle_clear(sig, d, correlation, fingerprint, unit)
        else:
            inc = self._handle_info(sig, unit)

        # 先固定原始归属，再做关联合并；合并会把被吸收事件记录的
        # final 改写到存活事件并追加 merged_via，保证两段都可追溯
        rec.original_incident_id = inc.id if inc is not None else None
        rec.final_incident_id = rec.original_incident_id
        self._relate_and_merge(ts)
        if inc is not None and inc.merged_into:
            inc = self.incidents[inc.merged_into]
            rec.final_incident_id = inc.id

        if inc is not None:
            self._pump(inc, ts)
        return inc

    @staticmethod
    def _infer_kind(d: AlarmDef) -> str:
        return SIGNAL_CLEAR if d.clearance_for else SIGNAL_RAISE

    # ---------------- raise ----------------
    def _handle_raise(self, sig: Signal, d: AlarmDef,
                      correlation: frozenset[tuple[str, str]],
                      fingerprint: str, unit: str | None) -> Incident:
        inc = self._find_open_for_evidence(sig.device_id, d.incident_type,
                                           correlation)
        created_incident = inc is None
        if inc is None:
            self._inc_seq += 1
            inc_id = f"INC-{self._inc_seq:04d}"
            inc = Incident(inc_id, d.incident_type, sig.ts,
                           sig.severity or d.default_severity)
            if unit:
                inc.units.add(unit)
            self.incidents[inc_id] = inc
            self._audit(sig.ts, "incident-opened",
                        f"{d.title} @ {sig.device_id}",
                        detail={"incident_id": inc.id, "type": inc.type,
                                "signal_seq": sig.seq})

        device_was_known = sig.device_id in inc.devices
        existed_active = any(
            e.active for e in inc.evidence.values()
            if e.device_id == sig.device_id and e.code == sig.code
            and e.correlation == correlation
        )
        ev, new_evidence, escalated = inc.add_raise(
            sig, code=d.code, correlation=correlation,
            root_cause=d.root_cause, unit=unit)

        if created_incident:
            self._arm_playbook(inc, sig.ts, d)

        # 观察期内复发：退出观察期回到处置中（已完成的剧本不自动重跑，
        # 复发后的复位动作必须重新经人工/许可裁决，杜绝"自动再复位"）
        if inc.state == "monitoring":
            inc.transit("mitigating", sig.ts)
            self._monitoring_deadline.pop(inc.id, None)
            self._audit(sig.ts, "incident-reopened",
                        f"观察期内故障复发: {sig.device_id}:{sig.code}",
                        detail={"incident_id": inc.id})

        self._notify_raise(inc, sig, d, fingerprint, created_incident,
                           new_evidence, existed_active, escalated, ev, unit,
                           device_was_known)
        return inc

    def _notify_raise(self, inc: Incident, sig: Signal, d: AlarmDef,
                      fingerprint: str, created_incident: bool,
                      new_evidence: bool, existed_active: bool,
                      escalated: bool, ev: Any, unit: str | None,
                      device_was_known: bool) -> None:
        if not d.notify:
            return
        sev = sig.severity or inc.severity
        if created_incident:
            self.notifications.evaluate(
                ts=sig.ts, key=f"event:{inc.id}", window_ms=0,
                severity=sev, incident_id=inc.id, force=True,
                also_seed=(f"fp:{fingerprint}",),
                title=f"[新事件 {inc.id}] {d.title}",
                body=f"{sig.device_id} 报 {sig.code}，单元 {unit or '?'}，"
                     f"级别 {sev.name}",
            )
        elif escalated:
            # 严重度升级：独立键 + force，且 evaluate 内部对同键升级也会穿透
            self.notifications.evaluate(
                ts=sig.ts, key=f"event:{inc.id}:severity", window_ms=0,
                severity=sev, incident_id=inc.id, force=True,
                also_seed=(f"fp:{fingerprint}",),
                title=f"[严重度升级 {inc.id}] -> {sev.name}",
                body=f"{sig.device_id}:{sig.code} 将事件级别推高至 {sev.name}",
            )
        elif new_evidence and not device_was_known:
            self.notifications.evaluate(
                ts=sig.ts, key=f"spread:{fingerprint}", window_ms=0,
                severity=sev, incident_id=inc.id, force=True,
                also_seed=(f"fp:{fingerprint}",),
                title=f"[故障扩散 {inc.id}] {sig.device_id}:{sig.code}",
                body=f"事件新增受影响设备 {sig.device_id}（单元 {unit or '?'}）",
            )
        else:
            # 同指纹短时抖动：窗口内抑制；严重度高于上次已发则强制穿透
            self.notifications.evaluate(
                ts=sig.ts, key=f"fp:{fingerprint}",
                window_ms=d.dedup_window_ms, severity=sev,
                incident_id=inc.id, active_duplicate=existed_active,
                title=f"[重复抖动 {inc.id}] {d.title}",
                body=f"{sig.device_id}:{sig.code} 已累计出现 "
                     f"{ev.raised_count} 次",
            )

    # ---------------- clear ----------------
    def _handle_clear(self, sig: Signal, d: AlarmDef,
                      correlation: frozenset[tuple[str, str]],
                      fingerprint: str, unit: str | None) -> Incident | None:
        target_codes = d.clearance_for
        matched = self._find_incidents_for_clear(
            sig.device_id, target_codes, correlation, only_open=True)
        if not matched:
            # 晚到/无对应活动证据：找历史事件挂联，仅留痕，绝不关闭任何事件
            host = self._find_historical_host(sig.device_id, target_codes)
            self._audit(sig.ts, "clear-ignored-stale",
                        f"恢复信号 {sig.code} 无活动证据可熄灭",
                        actor=f"signal:{sig.device_id}", team="field",
                        detail={"signal_seq": sig.seq,
                                "host_incident": host.id if host else None})
            self.notifications.evaluate(
                ts=sig.ts, key=f"stale-clear:{fingerprint}",
                window_ms=0, severity=Severity.INFO,
                incident_id=host.id if host else None, force=True,
                title="[恢复信号晚到，未改变事件状态]",
                body=f"{sig.device_id}:{sig.code} 找不到活动证据，"
                     f"任何事件均未被关闭",
            )
            return host

        for inc in matched:
            cleared = inc.apply_clear(
                sig, target_codes=target_codes,
                correlation=correlation, unit=unit)
            if cleared:
                self._audit(sig.ts, "evidence-cleared",
                            f"{sig.device_id} 恢复，熄灭 {len(cleared)} 条证据",
                            actor=f"signal:{sig.device_id}", team="field",
                            detail={"incident_id": inc.id,
                                    "codes": [e.code for e in cleared],
                                    "signal_seq": sig.seq})
                self.notifications.evaluate(
                    ts=sig.ts, key=f"recover:{fingerprint}",
                    window_ms=0, severity=Severity.INFO,
                    incident_id=inc.id, force=True,
                    title=f"[设备恢复 {inc.id}] {sig.device_id}",
                    body=f"{sig.device_id}:{sig.code} 已恢复"
                         + ("" if inc.active_evidence else
                            "，事件全部证据已恢复"),
                )
                if not inc.active_evidence:
                    self._on_all_evidence_cleared(inc, sig.ts)
        return matched[0]

    def _on_all_evidence_cleared(self, inc: Incident, ts: int) -> None:
        """全部证据恢复后的行为。

        * 人工/安全接管中：只提示，结案权在人；
        * 无剧本：立即自动结案；
        * 剧本未走完：保持处置中（恢复顺序可能早于复位回调，
          由步骤前置条件继续裁决）；
        * 剧本已走完：进入观察期，tick 到点无复发才自动结案。
        """
        if inc.under_human_control():
            self._audit(ts, "awaiting-human-close",
                        "全部证据恢复，但事件在人工控制下，等待人工结案",
                        detail={"incident_id": inc.id,
                                "owner": inc.control_owner})
            return
        run = self.runs.get(inc.id)
        if run is None:
            inc.close(ts, "无剧本事件全部证据恢复，自动结案")
            self._audit(ts, "incident-auto-closed",
                        "全部证据恢复且无处置剧本",
                        detail={"incident_id": inc.id})
            return
        if not run.is_done():
            self._audit(ts, "recovery-before-playbook-done",
                        "证据已全部恢复但剧本尚有步骤，按前置条件继续裁决",
                        detail={"incident_id": inc.id,
                                "pending_step":
                                    run.current.step_id if run.current else None})
            return
        if inc.state != "monitoring":
            inc.transit("monitoring", ts)
        deadline = ts + self.auto_close_grace_ms
        self._monitoring_deadline[inc.id] = deadline
        self._audit(ts, "monitoring-started",
                    f"剧本完成且全部证据恢复，进入观察期至 {deadline}",
                    detail={"incident_id": inc.id})

    # ---------------- info ----------------
    def _handle_info(self, sig: Signal, unit: str | None) -> Incident | None:
        inc = self._find_open_for_device(sig.device_id)
        if inc is not None:
            inc.attach_info(sig)
        return inc

    # ================================================================
    # 事件检索与关联合并
    # ================================================================
    def _open_incidents(self) -> list[Incident]:
        return [i for i in self.incidents.values()
                if i.state != "closed" and i.merged_into is None]

    def _find_open_for_evidence(self, device_id: str, incident_type: str,
                                correlation: frozenset[tuple[str, str]]
                                ) -> Incident | None:
        for inc in self._open_incidents():
            if inc.type != incident_type:
                continue
            if device_id in inc.devices:
                return inc
            if correlation and any(
                    correlation & g for g in inc.correlation_groups):
                return inc
        # 拓扑传播：新设备位于某事件根因证据设备的下游 -> 同一故障事件
        topo = self.topo.version_at(self.now)
        for inc in self._open_incidents():
            if inc.type != incident_type:
                continue
            for ev in inc.active_evidence:
                if ev.root_cause and device_id in downstream(
                        topo, ev.device_id):
                    return inc
        return None

    def _find_open_for_device(self, device_id: str) -> Incident | None:
        for inc in self._open_incidents():
            if device_id in inc.devices:
                return inc
        return None

    def _find_incidents_for_clear(self, device_id: str, target_codes: Sequence[str],
                                  correlation: frozenset[tuple[str, str]],
                                  *, only_open: bool) -> list[Incident]:
        out: list[Incident] = []
        pool = self._open_incidents() if only_open else list(self.incidents.values())
        for inc in pool:
            for ev in inc.active_evidence:
                if ev.device_id != device_id or ev.code not in target_codes:
                    continue
                if correlation and not correlation.issubset(ev.correlation):
                    continue
                out.append(inc)
                break
        return out

    def _find_historical_host(self, device_id: str,
                              target_codes: Sequence[str]) -> Incident | None:
        """晚到恢复挂靠到最近一个曾有该证据的存活事件（含已结案），仅为可追溯。"""
        best: Incident | None = None
        for inc in self.incidents.values():
            if inc.merged_into is not None:
                continue
            for ev in inc.evidence.values():
                if ev.device_id == device_id and ev.code in target_codes:
                    if best is None or inc.updated_ts > best.updated_ts:
                        best = inc
        return best

    def _relate_and_merge(self, ts: int) -> None:
        """同类型事件：共享关联维度 或 拓扑上下游存在根因证据 -> 合并。"""
        changed = True
        while changed:
            changed = False
            open_incs = self._open_incidents()
            for i in range(len(open_incs)):
                for j in range(i + 1, len(open_incs)):
                    a, b = open_incs[i], open_incs[j]
                    if a.type != b.type:
                        continue
                    if self._should_merge(a, b, ts):
                        self._merge(a, b, ts)
                        changed = True
                        break
                if changed:
                    break

    def _should_merge(self, a: Incident, b: Incident, ts: int) -> bool:
        if any(ga & gb for ga in a.correlation_groups
               for gb in b.correlation_groups):
            return True
        topo = self.topo.version_at(ts)

        def _merge_by_propagation(root_inc: Incident,
                                  evidence_inc: Incident) -> bool:
            roots = {e.device_id for e in root_inc.active_evidence
                     if e.root_cause}
            affected = {e.device_id for e in evidence_inc.active_evidence}
            for r in roots:
                if affected & (set(downstream(topo, r)) - {r}):
                    return True
            return False

        return _merge_by_propagation(a, b) or _merge_by_propagation(b, a)

    def _merge(self, survivor: Incident, other: Incident, ts: int) -> None:
        old_other_id = other.id
        survivor_run = self.runs.get(survivor.id)
        other_run = self.runs.get(old_other_id)
        survivor.absorb(other, ts)
        # 剧本实例归属：存活事件无剧本则收养；否则终止被合并方的实例
        if survivor_run is None and other_run is not None:
            other_run.incident_id = survivor.id
            self.runs[survivor.id] = other_run
            del self.runs[old_other_id]
        elif other_run is not None and not other_run.is_done():
            other_run.pause(ts, f"所属事件 {old_other_id} 已合并入 {survivor.id}")
        # 信号台账改挂最终事件，保留合并链路（original 已先固定）
        for rec in self.ledger.all():
            if rec.final_incident_id == old_other_id:
                rec.final_incident_id = survivor.id
                if old_other_id not in rec.merged_via:
                    rec.merged_via = rec.merged_via + (old_other_id,)
        self._monitoring_deadline.pop(old_other_id, None)
        self._audit(ts, "incidents-merged",
                    f"{old_other_id} 关联合并入 {survivor.id}",
                    detail={"survivor": survivor.id, "absorbed": old_other_id})
        self.notifications.evaluate(
            ts=ts, key=f"merge:{survivor.id}:{old_other_id}",
            window_ms=0, severity=survivor.severity,
            incident_id=survivor.id, force=True,
            title=f"[事件合并] {old_other_id} -> {survivor.id}",
            body=f"共享根因/关联维度，合并后受影响单元 "
                 f"{sorted(survivor.units)}",
        )

    # ================================================================
    # 剧本装配与推进
    # ================================================================
    def _arm_playbook(self, inc: Incident, ts: int, d: AlarmDef) -> None:
        pbdef = (self.playbooks.get(d.playbook) if d.playbook
                 else self.playbooks.for_incident_type(inc.type))
        if pbdef is None:
            return
        run = PlaybookInstance(f"RUN-{inc.id}", inc.id, pbdef, ts)
        self.runs[inc.id] = run
        if pbdef.auto_arm:
            run.activate(ts)
            if inc.state == "open":
                inc.transit("mitigating", ts)
            self._audit(ts, "playbook-armed",
                        f"剧本 {pbdef.playbook_id} 自动挂载并激活",
                        detail={"incident_id": inc.id,
                                "playbook": pbdef.playbook_id})

    def _target_device(self, inc: Incident, step: StepDef) -> tuple[str, str | None]:
        """返回 (device_id, unit)。"""
        if step.target == "first_evidence":
            ev = next(iter(inc.active_evidence), None)
            if ev is None:
                ev = next(iter(inc.evidence.values()), None)
            if ev is None:
                return "", None
            return ev.device_id, self._unit_of(ev.device_id, inc)
        if step.target == "root_cause":
            topo = self.topo.version_at(self.now)
            cands = inc.root_cause_candidates(topo, limit=1)
            if cands:
                return cands[0].device_id, self._unit_of(cands[0].device_id, inc)
            # 证据全部恢复后（如复位步骤）：回退到历史根因设备而非阻断
            ev = next(iter(inc.active_evidence), None)
            if ev is None:
                historical = [e for e in inc.evidence.values() if e.root_cause]
                ev = historical[0] if historical else next(
                    iter(inc.evidence.values()), None)
            if ev is None:
                return "", None
            return ev.device_id, self._unit_of(ev.device_id, inc)
        return step.target, self._unit_of(step.target, inc)

    def _unit_of(self, device_id: str, inc: Incident) -> str | None:
        topo = self.topo.version_at(self.now)
        dev = topo.devices.get(device_id)
        if dev is not None:
            return dev.unit
        return next(iter(inc.units), None)

    def _compensation_in_flight(self, sr: Any) -> bool:
        return bool(sr.dispatch_id
                    and self.gateway.peek(sr.dispatch_id) is not None)

    def _pump(self, inc: Incident, ts: int) -> None:
        """尝试推进剧本当前步骤；每次都重新求值许可与前置条件。"""
        run = self.runs.get(inc.id)
        if (run is None or run.status == "armed" or run.is_done()
                or run.paused or inc.state == "closed"):
            return
        step = run.current
        sr = run.current_run
        if step is None or sr is None:
            return
        if sr.state == STEP_RUNNING:
            return  # 等回调；超时由 tick 处理
        if sr.state == STEP_COMPENSATING:
            # 许可恢复后在 tick/事件驱动下重试补偿；在飞则不重发
            if not self._compensation_in_flight(sr):
                self._begin_or_run_compensation(
                    inc, run, step, sr, ts,
                    sr.wait_reason or "重新尝试补偿动作")
            return
        if step.mode == MODE_MANUAL:
            self._hold_waiting(run, sr, ts, "等待人工现场处置并回填")
            return

        # 自动步骤：前置条件（每次重新求值）。reason 变化时才新增留痕，
        # 避免 tick 泵推反复刷审计。
        for pred_name in step.preconditions:
            fn = self._preconditions.get(pred_name)
            if fn is None:
                self._hold_waiting(
                    run, sr, ts,
                    f"未知前置条件 {pred_name}，安全默认阻断")
                return
            ok, why = fn(EngineContext(self), inc, run, step, ts)
            if not ok:
                self._hold_waiting(
                    run, sr, ts,
                    f"前置条件未满足[{pred_name}]: {why}")
                return

        target, unit = self._target_device(inc, step)
        if not target:
            self._hold_waiting(run, sr, ts,
                               "无法解析目标设备（无证据设备）")
            return

        # 人工/安全接管：自动动作只影子留痕，绝不下发
        if inc.under_human_control():
            reason = (f"控制权在 {inc.control_owner}，"
                      f"自动步骤仅影子留痕不执行")
            changed = self._hold_waiting(run, sr, ts, reason)
            if changed:
                self._audit(ts, "auto-step-shadow",
                            f"步骤 {step.step_id} 因人工接管未下发",
                            detail={"incident_id": inc.id,
                                    "step": step.step_id,
                                    "owner": inc.control_owner})
            return

        decision = self.safety.allowed(
            device=target, unit=unit or "unknown",
            action=step.permit_action, ts=ts)
        if not decision.allowed:
            reason = f"安全裁决拒绝: {decision.reason}"
            changed = self._hold_waiting(run, sr, ts, reason)
            if changed:
                self._audit(ts, "auto-step-blocked",
                            f"步骤 {step.step_id} 被安全裁决阻断",
                            detail={"incident_id": inc.id,
                                    "step": step.step_id,
                                    "device": target,
                                    "reason": decision.reason})
            return

        self._dispatch(inc, run, step, sr, target, ts, kind="action",
                       action=step.action or step.permit_action,
                       timeout_ms=step.timeout_ms)

    def _hold_waiting(self, run: PlaybookInstance, sr: Any, ts: int,
                      reason: str) -> bool:
        """幂等等待：已处于 waiting 且原因未变时不重复留痕，返回是否发生变化。"""
        if sr.state == STEP_WAITING and sr.wait_reason == reason:
            return False
        run.mark_waiting(sr, ts, reason)
        return True

    def _dispatch(self, inc: Incident, run: PlaybookInstance, step: StepDef,
                  sr: Any, target: str, ts: int, *, kind: str,
                  action: str, timeout_ms: int | None) -> None:
        self._dispatch_seq += 1
        dispatch_id = f"DSP-{self._dispatch_seq:05d}"
        accepted, reason = self.gateway.send(
            dispatch_id=dispatch_id, incident_id=inc.id,
            instance_id=run.instance_id, step_id=step.step_id, kind=kind,
            device_id=target, action=action, ts=ts,
            payload={"incident_type": inc.type, "severity": inc.severity.name},
        )
        if not accepted:
            run.mark_waiting(sr, ts, f"设备侧拒绝受理: {reason}")
            return
        sr.attempts += 1
        sr.dispatch_id = dispatch_id
        sr.dispatched_ts = ts
        if kind == "compensation":
            run.begin_compensation(sr, ts,
                                   f"补偿指令 {action} 已下发，等待回调")
        else:
            run.mark_running(sr, ts, dispatch_id, timeout_ms)
        self._audit(ts, "command-dispatched",
                    f"{kind} {action} -> {target}",
                    detail={"incident_id": inc.id, "step": step.step_id,
                            "dispatch_id": dispatch_id,
                            "permit_action": step.permit_action})

    # ================================================================
    # 设备回调（迟到/接管后的处理是本系统的安全关键）
    # ================================================================
    def handle_callback(self, *, dispatch_id: str, instance_id: str,
                        step_id: str, success: bool, ts: int,
                        detail: str = "") -> tuple[str, AuditEvent]:
        self.now = max(self.now, ts)
        # 先用 peek 校验身份，校验通过才消费，防止错误回调吞掉合法挂起指令
        cmd = self.gateway.peek(dispatch_id)
        if cmd is None:
            audit = self._audit(ts, "callback-ignored",
                                "未知/重复/已注销回调，不改变任何状态",
                                detail={"dispatch_id": dispatch_id,
                                        "instance_id": instance_id,
                                        "step_id": step_id, "success": success})
            return CallbackVerdict.IGNORED, audit
        inc = self.incidents.get(cmd.incident_id)
        run = self.runs.get(cmd.incident_id)
        if (inc is None or run is None or run.instance_id != instance_id
                or cmd.step_id != step_id):
            audit = self._audit(ts, "callback-ignored",
                                "回调身份与执行实例/步骤不符，已丢弃且未消费挂起指令",
                                detail={"dispatch_id": dispatch_id,
                                        "instance_id": instance_id,
                                        "step_id": step_id,
                                        "expected_instance":
                                            run.instance_id if run else None,
                                        "expected_step": cmd.step_id})
            return CallbackVerdict.IGNORED, audit
        self.gateway.resolve(dispatch_id)

        # 安全关键裁决：人工/安全接管后、或下发早于当前控制权生效时间、
        # 或事件已结案 -> 回调只做影子留痕，绝不夺回控制权、不复位设备
        shadow = (
            inc.under_human_control()
            or inc.control.since_ts > cmd.ts
            or inc.state == "closed"
        )
        sr = run.run_of(step_id)
        if shadow:
            audit = self._audit(
                ts, "callback-shadow-only",
                f"回调 success={success} 到达但不夺回控制权，仅留痕",
                detail={"incident_id": inc.id, "dispatch_id": dispatch_id,
                        "step": step_id, "owner": inc.control_owner,
                        "incident_state": inc.state})
            sr.note(ts, "callback-shadow",
                    f"success={success} ({detail})，未应用")
            return CallbackVerdict.SHADOW, audit

        if not success:
            step = run.current
            if (cmd.kind == "action" and step is not None
                    and step.step_id == step_id and step.compensation
                    and step.on_timeout == ON_TIMEOUT_COMPENSATE):
                self._begin_or_run_compensation(
                    inc, run, step, sr, ts, f"回调报告失败: {detail}")
            else:
                run.mark_failed(sr, ts, f"回调失败且无补偿: {detail}")
                self._notify_playbook_failure(inc, ts, step_id, detail)
            return CallbackVerdict.APPLIED, self.audits[-1]

        if cmd.kind == "compensation":
            # 补偿成功也意味着原步骤失败，设备已被带到安全位，转人工
            run.mark_failed(sr, ts,
                            f"补偿动作执行完成: {detail}，等待人工介入")
            self._notify_playbook_failure(
                inc, ts, step_id, "补偿已完成，设备处于安全位，等待人工")
            return CallbackVerdict.APPLIED, self.audits[-1]

        run.mark_completed(sr, ts, detail)
        self._audit(ts, "step-completed",
                    f"步骤 {step_id} 回调成功完成",
                    detail={"incident_id": inc.id,
                            "dispatch_id": dispatch_id})
        if run.is_done() and not inc.active_evidence:
            self._on_all_evidence_cleared(inc, ts)
        else:
            self._pump(inc, ts)
        return CallbackVerdict.APPLIED, self.audits[-1]

    # ================================================================
    # 超时与补偿（tick 驱动）
    # ================================================================
    def tick(self, now: int) -> None:
        self.now = max(self.now, now)
        for inc in list(self.incidents.values()):
            if inc.state == "closed" or inc.merged_into:
                continue
            run = self.runs.get(inc.id)
            if run is not None and not run.paused and run.status != "armed":
                self._check_timeouts(inc, run, now)
                self._pump(inc, now)
            self._check_monitoring_close(inc, now)

    def _check_timeouts(self, inc: Incident, run: PlaybookInstance,
                        now: int) -> None:
        step = run.current
        sr = run.current_run
        if step is None or sr is None or sr.state != STEP_RUNNING:
            return
        if sr.deadline_ts is None or now < sr.deadline_ts:
            return

        # 接管后超时：不自行补偿，交人工；注销旧指令身份，其回调随后被忽略
        if inc.under_human_control() or inc.control.since_ts > (sr.dispatched_ts or 0):
            stale = sr.dispatch_id
            if stale:
                self.gateway.cancel(stale)
                sr.dispatch_id = None
            run.mark_waiting(
                sr, now,
                f"步骤在人工接管后超时(dispatch={stale})，交人工处置")
            self._audit(now, "timeout-shadow",
                        f"步骤 {step.step_id} 超时但控制权在人工侧，未自动补偿",
                        detail={"incident_id": inc.id, "step": step.step_id})
            self.notifications.evaluate(
                ts=now, key=f"timeout-shadow:{inc.id}:{step.step_id}",
                window_ms=0, severity=inc.severity, incident_id=inc.id,
                force=True, title=f"[接管后超时 {inc.id}] {step.step_id}",
                body="自动动作超时，因人工接管未执行补偿，等待人工判定",
            )
            return

        if step.on_timeout != ON_TIMEOUT_COMPENSATE or not step.compensation:
            # 超时指令已不可能按预期完成：注销挂起身份，迟到回调将被忽略
            if sr.dispatch_id:
                self.gateway.cancel(sr.dispatch_id)
                sr.dispatch_id = None
            run.mark_failed(sr, now, "执行超时且无补偿动作")
            self._audit(now, "step-timeout-failed",
                        f"步骤 {step.step_id} 超时失败",
                        detail={"incident_id": inc.id})
            self._notify_playbook_failure(inc, now, step.step_id, "执行超时")
            return

        # 注销超时的原动作挂起身份（其迟到回调随后被 IGNORED），再启动补偿
        stale_dispatch = sr.dispatch_id
        if stale_dispatch:
            self.gateway.cancel(stale_dispatch)
            sr.dispatch_id = None
        self._audit(now, "step-timed-out",
                    f"步骤 {step.step_id} 超时，挂起指令 {stale_dispatch} 注销",
                    detail={"incident_id": inc.id,
                            "stale_dispatch": stale_dispatch})
        self._begin_or_run_compensation(
            inc, run, step, sr, now, f"执行超过 {step.timeout_ms}ms 时限")

    def _begin_or_run_compensation(self, inc: Incident, run: PlaybookInstance,
                                   step: StepDef, sr: Any, ts: int,
                                   reason: str) -> None:
        if self._compensation_in_flight(sr):
            return
        entering = sr.state != STEP_COMPENSATING
        if entering:
            run.begin_compensation(sr, ts, reason)
            self._audit(ts, "compensation-started",
                        f"步骤 {step.step_id} 进入补偿: {reason}",
                        detail={"incident_id": inc.id, "step": step.step_id})
            self.notifications.evaluate(
                ts=ts, key=f"comp:{inc.id}:{step.step_id}",
                window_ms=0, severity=Severity.CRITICAL, incident_id=inc.id,
                force=True,
                title=f"[补偿启动 {inc.id}] {step.step_id}",
                body=f"原动作失败/超时：{reason}",
            )
        target, unit = self._target_device(inc, step)
        # 补偿同样受控制权约束：接管后只留痕
        if inc.under_human_control():
            blocked_reason = (f"控制权在 {inc.control_owner}，补偿不下发")
            self._hold_compensation(run, sr, ts, blocked_reason, inc, step,
                                    entering)
            return
        decision = self.safety.allowed(
            device=target, unit=unit or "unknown",
            action=step.comp_permit_action, ts=ts)
        if not decision.allowed:
            blocked_reason = f"补偿被安全裁决阻断: {decision.reason}"
            self._hold_compensation(run, sr, ts, blocked_reason, inc, step,
                                    entering)
            return
        self._dispatch(inc, run, step, sr, target, ts, kind="compensation",
                       action=step.compensation, timeout_ms=step.timeout_ms)

    def _hold_compensation(self, run: PlaybookInstance, sr: Any, ts: int,
                           reason: str, inc: Incident, step: StepDef,
                           entering: bool) -> None:
        """补偿等待幂等：原因未变的后续 tick 只等待，不重复通知/审计。"""
        if not entering and sr.state == STEP_COMPENSATING \
                and sr.wait_reason == reason:
            return
        run.hold_compensation(sr, ts, reason)
        self._audit(ts, "compensation-blocked",
                    f"补偿动作 {step.compensation} 被阻断: {reason}",
                    detail={"incident_id": inc.id, "step": step.step_id})
        self.notifications.evaluate(
            ts=ts, key=f"comp-blocked:{inc.id}:{step.step_id}",
            window_ms=0, severity=Severity.CRITICAL, incident_id=inc.id,
            force=True,
            title=f"[补偿被安全阻断 {inc.id}] {step.step_id}",
            body=f"补偿无法执行：{reason}，设备保持安全位",
        )

    def _notify_playbook_failure(self, inc: Incident, ts: int, step_id: str,
                                 detail: str) -> None:
        self.notifications.evaluate(
            ts=ts, key=f"fail:{inc.id}:{step_id}", window_ms=0,
            severity=Severity.CRITICAL, incident_id=inc.id, force=True,
            title=f"[剧本失败 {inc.id}] 步骤 {step_id}",
            body=f"剧本步骤失败，需人工介入: {detail}",
        )

    def _check_monitoring_close(self, inc: Incident, now: int) -> None:
        deadline = self._monitoring_deadline.get(inc.id)
        if deadline is None or now < deadline:
            return
        self._monitoring_deadline.pop(inc.id, None)
        if inc.active_evidence or inc.under_human_control():
            return
        inc.close(now, "观察期内未复发，自动结案")
        self._audit(now, "incident-auto-closed",
                    "观察期结束自动结案", detail={"incident_id": inc.id})
        self.notifications.evaluate(
            ts=now, key=f"closed:{inc.id}", window_ms=0,
            severity=Severity.INFO, incident_id=inc.id, force=True,
            title=f"[自动结案 {inc.id}]",
            body="观察期内故障未复发，事件结案",
        )

    # ================================================================
    # 人工动作（全部带班组与理由）
    # ================================================================
    def _require_open(self, incident_id: str) -> Incident:
        inc = self.incidents.get(incident_id)
        if inc is None:
            raise KeyError(f"未知事件: {incident_id}")
        if inc.state == "closed" or inc.merged_into:
            raise ValueError(f"事件 {incident_id} 已结案/已合并")
        return inc

    def acknowledge(self, incident_id: str, *, actor: str, team: str,
                    reason: str, ts: int) -> Incident:
        inc = self._require_open(incident_id)
        if inc.acknowledged_ts is None:
            inc.acknowledged_ts = ts
        if inc.state == "open":
            inc.transit("acknowledged", ts)
        self._audit(ts, "incident-acknowledged", reason, actor=actor, team=team,
                    detail={"incident_id": inc.id})
        self._pump(inc, ts)
        return inc

    def take_control(self, incident_id: str, *, actor: str, team: str,
                     reason: str, ts: int,
                     owner: str = OWNER_OPERATOR) -> Incident:
        inc = self._require_open(incident_id)
        if owner not in (OWNER_OPERATOR, OWNER_SAFETY):
            raise ValueError("人工接管 owner 只能是 operator 或 safety")
        inc.take_control(owner, ts, actor, team, reason)
        self._audit(ts, "control-taken", reason, actor=actor, team=team,
                    detail={"incident_id": inc.id, "owner": owner})
        # 仅人工剧本（如急停）在人工接管时正式激活
        run = self.runs.get(incident_id)
        if run is not None and run.status == "armed":
            run.activate(ts)
            self._audit(ts, "playbook-activated",
                        "人工接管，仅人工处置剧本激活",
                        actor=actor, team=team,
                        detail={"incident_id": inc.id})
        self._pump(inc, ts)
        return inc

    def handback(self, incident_id: str, *, actor: str, team: str,
                 reason: str, ts: int) -> Incident:
        """人工把控制权交还自动侧。接管前已下发的回调仍按影子处理。"""
        inc = self._require_open(incident_id)
        inc.take_control(OWNER_AUTOMATION, ts, actor, team, reason)
        self._audit(ts, "control-handback", reason, actor=actor, team=team,
                    detail={"incident_id": inc.id})
        self._pump(inc, ts)
        return inc

    def transfer(self, incident_id: str, to_team: str, *, actor: str,
                 team: str, reason: str, ts: int) -> Incident:
        """转派给另一班组：控制权留在人工侧，班组变更全程留痕。"""
        inc = self._require_open(incident_id)
        owner = (OWNER_OPERATOR if inc.control_owner == OWNER_AUTOMATION
                 else inc.control_owner)
        inc.take_control(owner, ts, actor, to_team, reason)
        self._audit(ts, "incident-transferred", reason, actor=actor, team=team,
                    detail={"incident_id": inc.id, "to_team": to_team})
        return inc

    def pause_playbook(self, incident_id: str, *, actor: str, team: str,
                       reason: str, ts: int) -> Incident:
        inc = self._require_open(incident_id)
        run = self.runs.get(incident_id)
        if run is None:
            raise ValueError(f"事件 {incident_id} 无在执行剧本")
        run.pause(ts, reason)
        self._audit(ts, "playbook-paused", reason, actor=actor, team=team,
                    detail={"incident_id": inc.id,
                            "step": run.current.step_id if run.current else None})
        return inc

    def resume_playbook(self, incident_id: str, *, actor: str, team: str,
                        reason: str, ts: int) -> Incident:
        inc = self._require_open(incident_id)
        run = self.runs.get(incident_id)
        if run is None or not run.paused:
            raise ValueError("剧本未处于暂停状态")
        run.resume(ts)
        self._audit(ts, "playbook-resumed", reason, actor=actor, team=team,
                    detail={"incident_id": inc.id})
        self._pump(inc, ts)
        return inc

    def complete_manual_step(self, incident_id: str, step_id: str, *,
                             actor: str, team: str, note: str,
                             ts: int) -> Incident:
        inc = self._require_open(incident_id)
        run = self.runs.get(incident_id)
        if run is None:
            raise ValueError("事件无剧本")
        step = run.current
        sr = run.current_run
        if step is None or step.step_id != step_id or step.mode != MODE_MANUAL:
            raise ValueError(f"{step_id} 不是当前等待的人工步骤")
        run.mark_completed(sr, ts, f"{actor}/{team}: {note}")
        self._audit(ts, "manual-step-completed", note, actor=actor, team=team,
                    detail={"incident_id": inc.id, "step": step_id})
        self._pump(inc, ts)
        return inc

    def close_incident(self, incident_id: str, *, actor: str, team: str,
                       reason: str, ts: int) -> Incident:
        inc = self._require_open(incident_id)
        run = self.runs.get(incident_id)
        if run is not None and not run.is_done():
            run.pause(ts, f"事件人工结案，剧本终止: {reason}")
        inc.close(ts, reason, force=True)
        self._monitoring_deadline.pop(incident_id, None)
        self._audit(ts, "incident-closed", reason, actor=actor, team=team,
                    detail={"incident_id": inc.id,
                            "residual_blockers": inc.close_blockers()})
        self.notifications.evaluate(
            ts=ts, key=f"human-closed:{inc.id}", window_ms=0,
            severity=Severity.INFO, incident_id=inc.id, force=True,
            title=f"[人工结案 {inc.id}]",
            body=f"{team}/{actor}: {reason}",
        )
        return inc

    # ================================================================
    # 安全许可包装：撤销即审计，并联动收回自动控制权
    # ================================================================
    def grant_permit(self, scope_type: str, scope: str, action: str, ts: int,
                     *, reason: str = "", granted_by: str = "safety-system"):
        p = self.safety.grant(scope_type, scope, action, ts, reason, granted_by)
        self._audit(ts, "permit-granted", reason or f"许可 {action} 签发",
                    actor=granted_by, team="safety",
                    detail={"scope_type": scope_type, "scope": scope,
                            "action": action})
        for inc in self._open_incidents():
            run = self.runs.get(inc.id)
            if run is not None and not run.paused:
                self._pump(inc, ts)
        return p

    def revoke_permit(self, scope_type: str, scope: str, action: str, ts: int,
                      *, reason: str) -> None:
        revoked = self.safety.revoke(scope_type, scope, action, ts, reason)
        self._audit(ts, "permit-revoked", reason, actor="safety-officer",
                    team="safety",
                    detail={"scope_type": scope_type, "scope": scope,
                            "action": action, "found": revoked is not None})
        # 许可撤销：受影响事件立即收归安全控制，在飞动作的回调将只做影子
        for inc in self._open_incidents():
            run = self.runs.get(inc.id)
            if run is None:
                continue
            touched = any(
                step.permit_action == action
                or step.comp_permit_action == action
                for step in run.definition.steps
            )
            if not touched:
                continue
            if inc.control_owner == OWNER_AUTOMATION:
                inc.take_control(OWNER_SAFETY, ts, "safety-system", "safety",
                                 f"安全许可 {action} 撤销，自动侧收权")
                self._audit(ts, "control-taken",
                            f"许可撤销联动安全收权: {reason}",
                            actor="safety-system", team="safety",
                            detail={"incident_id": inc.id})
            self._pump(inc, ts)

    # ================================================================
    # 态势查询
    # ================================================================
    def open_incidents(self) -> tuple[Incident, ...]:
        return tuple(i for i in self.incidents.values()
                     if i.state != "closed" and i.merged_into is None)

    def root_cause_candidates(self, incident_id: str,
                              limit: int = 3):
        inc = self.incidents[incident_id]
        return inc.root_cause_candidates(self.topo.version_at(self.now), limit)

    def impacted_units(self, incident_id: str) -> tuple[str, ...]:
        inc = self.incidents[incident_id]
        topo = self.topo.version_at(self.now)
        return impacted_units(topo, list(inc.devices))

    def stuck_steps(self, incident_id: str) -> tuple[Mapping[str, Any], ...]:
        run = self.runs.get(incident_id)
        if run is None:
            return ()
        return run.stuck_steps()

    def situation_report(self, incident_id: str) -> Mapping[str, Any]:
        inc = self.incidents[incident_id]
        run = self.runs.get(incident_id)
        topo = self.topo.version_at(self.now)
        return {
            "incident": inc.snapshot(),
            "topology_version": topo.version,
            "impacted_units": list(self.impacted_units(incident_id)),
            "root_cause_candidates": [
                {"device": c.device_id, "score": c.score,
                 "rationale": c.rationale,
                 "supporting_codes": list(c.supporting_codes)}
                for c in inc.root_cause_candidates(topo)
            ],
            "control": {
                "owner": inc.control_owner,
                "since_ts": inc.control.since_ts,
                "actor": inc.control.actor,
                "team": inc.control.team,
                "reason": inc.control.reason,
                "handover_count": len(inc.history),
            },
            "playbook": None if run is None else run.snapshot(),
            "stuck_steps": list(self.stuck_steps(incident_id)),
            "notifications": [
                {"seq": n.seq, "ts": n.ts, "decision": n.decision,
                 "level": n.level, "title": n.title, "reason": n.reason}
                for n in self.notifications.history(incident_id)
            ],
            "evidence": [
                {"key": e.key, "device": e.device_id, "code": e.code,
                 "active": e.active, "raised_count": e.raised_count,
                 "first_ts": e.first_ts, "last_ts": e.last_ts,
                 "cleared_ts": e.cleared_ts,
                 "clear_seq": e.cleared_by_seq}
                for e in inc.evidence.values()
            ],
            "merged_children": list(inc.merged_children),
            "signals": list(inc.signal_seqs),
        }

    def audit_log(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(
            {"seq": a.seq, "ts": a.ts, "actor": a.actor, "team": a.team,
             "action": a.action, "reason": a.reason, "detail": a.detail}
            for a in self.audits
        )

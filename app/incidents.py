"""生产事件聚合。

一个 :class:`Incident` 是同一类故障在时间与关联维度上有边界的集合：

* 每条 raise 信号产生/激活一条**证据**；clear 信号只按 ``clearance_for``
  精确熄灭对应的一条证据。晚到的恢复信号若找不到活动证据（早已清除或属于
  已结案事件）不会产生任何关闭效果；
* 只要还存在任意活动证据，事件就**不能自动结案**——即使大部分设备已恢复；
* 事件合并时吸收对方全部证据、信号、审计记录，并保留父子关系可追溯；
* 控制权一旦被人工接管（operator/safety），自动侧只能"影子执行"留痕，
  绝不自动夺回。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from .model import (
    OWNER_AUTOMATION,
    Severity,
    Signal,
    can_transit,
    severity_value,
)


@dataclass
class Evidence:
    key: str
    device_id: str
    code: str
    correlation: frozenset[tuple[str, str]]
    root_cause: bool
    severity: Severity
    active: bool = True
    raised_count: int = 1
    first_ts: int = 0
    last_ts: int = 0
    cleared_ts: int | None = None
    cleared_by_seq: int | None = None
    raise_seqs: list[int] = field(default_factory=list)
    clear_seqs: list[int] = field(default_factory=list)

    def reactivate(self, ts: int, seq: int, severity: Severity) -> None:
        self.active = True
        self.raised_count += 1
        self.last_ts = ts
        self.cleared_ts = None
        self.cleared_by_seq = None
        self.severity = max(self.severity, severity)
        self.raise_seqs.append(seq)


def evidence_key(device_id: str, code: str,
                 correlation: frozenset[tuple[str, str]]) -> str:
    tail = "&".join(f"{k}={v}" for k, v in sorted(correlation))
    return f"{device_id}|{code}|{tail}"


@dataclass
class ControlRecord:
    owner: str
    since_ts: int
    actor: str
    team: str
    reason: str


@dataclass
class RootCauseCandidate:
    device_id: str
    score: int
    rationale: str
    supporting_codes: tuple[str, ...]
    correlated_evidence: int


class Incident:
    def __init__(self, incident_id: str, incident_type: str, ts: int,
                 severity: Severity):
        self.id = incident_id
        self.type = incident_type
        self.state = "open"
        self.created_ts = ts
        self.updated_ts = ts
        self.severity = severity
        self.initial_severity = severity
        self.evidence: dict[str, Evidence] = {}
        self.signal_seqs: list[int] = []
        self.devices: set[str] = set()
        self.units: set[str] = set()
        self.control = ControlRecord(
            OWNER_AUTOMATION, ts, actor="system", team="automation",
            reason="事件开启，默认可自动编排",
        )
        self.history: list[ControlRecord] = []
        self.merged_children: list[str] = []
        self.merged_into: str | None = None
        self.closed_ts: int | None = None
        self.close_reason: str | None = None
        self.escalated: bool = False
        self.acknowledged_ts: int | None = None
        self._correlation: set[frozenset[tuple[str, str]]] = set()

    # ---- 属性 ----
    @property
    def active_evidence(self) -> tuple[Evidence, ...]:
        return tuple(e for e in self.evidence.values() if e.active)

    @property
    def correlation_groups(self) -> tuple[frozenset[tuple[str, str]], ...]:
        return tuple(self._correlation)

    @property
    def can_auto_close(self) -> bool:
        return not self.active_evidence

    def close_blockers(self) -> tuple[str, ...]:
        """仍有哪些证据在支撑事件，阻止自动关闭。"""
        return tuple(
            f"{e.device_id}:{e.code}" for e in self.evidence.values() if e.active
        )

    # ---- 证据写入 ----
    def add_raise(
        self,
        sig: Signal,
        *,
        code: str,
        correlation: frozenset[tuple[str, str]],
        root_cause: bool,
        unit: str | None,
    ) -> tuple[Evidence, bool, bool]:
        """写入 raise 证据，返回 (证据, 是否新建, 是否严重度升级)。"""
        key = evidence_key(sig.device_id, code, correlation)
        sev = sig.severity or self.severity
        escalated = sev > self.severity
        existing = self.evidence.get(key)
        created = False
        if existing is None:
            created = True
            ev = Evidence(
                key=key, device_id=sig.device_id, code=code,
                correlation=correlation, root_cause=root_cause,
                severity=sev, first_ts=sig.ts, last_ts=sig.ts,
                raise_seqs=[sig.seq],
            )
            self.evidence[key] = ev
        else:
            if not existing.active:
                existing.reactivate(sig.ts, sig.seq, sev)
            else:
                existing.raised_count += 1
                existing.last_ts = sig.ts
                existing.raise_seqs.append(sig.seq)
                existing.severity = max(existing.severity, sev)
            ev = existing
        self.devices.add(sig.device_id)
        if unit:
            self.units.add(unit)
        if correlation:
            self._correlation.add(correlation)
        self.signal_seqs.append(sig.seq)
        if sev > self.severity:
            self.severity = sev
            self.escalated = True
        self.updated_ts = sig.ts
        return ev, created, escalated

    def apply_clear(
        self,
        sig: Signal,
        *,
        target_codes: Sequence[str],
        correlation: frozenset[tuple[str, str]],
        unit: str | None,
    ) -> tuple[Evidence, ...]:
        """按 clearance_for 精确熄灭证据。

        匹配规则：同设备、代码在 target_codes 中、clear 携带的关联键值都被
        证据包含。找不到活动证据时返回空元组——晚到恢复不得影响事件状态。
        """
        cleared: list[Evidence] = []
        for code in target_codes:
            for ev in self.evidence.values():
                if not ev.active:
                    continue
                if ev.device_id != sig.device_id or ev.code != code:
                    continue
                if correlation and not correlation.issubset(ev.correlation):
                    continue
                ev.active = False
                ev.cleared_ts = sig.ts
                ev.cleared_by_seq = sig.seq
                ev.clear_seqs.append(sig.seq)
                cleared.append(ev)
        self.signal_seqs.append(sig.seq)
        if unit:
            self.units.add(unit)
        self.updated_ts = sig.ts
        return tuple(cleared)

    def attach_info(self, sig: Signal) -> None:
        self.signal_seqs.append(sig.seq)
        self.updated_ts = sig.ts

    # ---- 控制权 ----
    def take_control(self, owner: str, ts: int, actor: str, team: str,
                     reason: str) -> ControlRecord:
        record = ControlRecord(owner, ts, actor, team, reason)
        self.history.append(self.control)
        self.control = record
        self.updated_ts = ts
        return record

    @property
    def control_owner(self) -> str:
        return self.control.owner

    def under_human_control(self) -> bool:
        return self.control.owner != OWNER_AUTOMATION

    # ---- 状态机 ----
    def transit(self, target: str, ts: int) -> None:
        if not can_transit(self.state, target):
            raise ValueError(f"非法事件状态迁移 {self.state} -> {target} ({self.id})")
        self.state = target
        self.updated_ts = ts
        if target == "closed":
            self.closed_ts = ts

    def close(self, ts: int, reason: str, *, force: bool = False) -> None:
        if not force and self.active_evidence:
            raise ValueError(
                f"事件 {self.id} 仍有活动证据，禁止自动结案: {self.close_blockers()}"
            )
        self.transit("closed", ts)
        self.close_reason = reason

    # ---- 合并 ----
    def absorb(self, other: "Incident", ts: int) -> None:
        """把 other 合并进 self。证据/信号/关联/控制历史全部保留。"""
        if other.id == self.id:
            return
        for key, ev in other.evidence.items():
            mine = self.evidence.get(key)
            if mine is None:
                self.evidence[key] = ev
            else:
                mine.raised_count += ev.raised_count
                mine.raise_seqs.extend(ev.raise_seqs)
                mine.clear_seqs.extend(ev.clear_seqs)
                mine.last_ts = max(mine.last_ts, ev.last_ts)
                mine.severity = max(mine.severity, ev.severity)
                if ev.active and mine.cleared_ts is not None:
                    mine.active = True
                    mine.cleared_ts = None
                    mine.cleared_by_seq = None
                elif ev.active:
                    mine.active = True
        self.signal_seqs.extend(other.signal_seqs)
        self.devices.update(other.devices)
        self.units.update(other.units)
        self._correlation.update(other._correlation)
        self.severity = max(self.severity, other.severity)
        if other.acknowledged_ts is not None:
            if self.acknowledged_ts is None:
                self.acknowledged_ts = other.acknowledged_ts
            else:
                self.acknowledged_ts = min(self.acknowledged_ts,
                                           other.acknowledged_ts)
        self.history.extend(other.history)
        if other.merged_children:
            for c in other.merged_children:
                if c not in self.merged_children:
                    self.merged_children.append(c)
        self.merged_children.append(other.id)
        other.merged_into = self.id
        other.state = "closed"
        other.closed_ts = ts
        other.close_reason = f"关联合并入 {self.id}"
        self.updated_ts = ts

    # ---- 根因候选 ----
    def root_cause_candidates(self, topo, limit: int = 3) -> list[RootCauseCandidate]:
        """按依赖传播与关联证据给根因设备打分。

        分数 = 该设备能向下游解释的其他活动证据设备数 * 3
               + 共享关联键（如同一个轴）的其他证据数 * 2
               + 该设备自身的活动 raise 数。
        只有 root_cause=True 的证据设备可作为候选。
        """
        active = self.active_evidence
        active_devices = {e.device_id for e in active}
        candidates: list[RootCauseCandidate] = []
        for ev in active:
            if not ev.root_cause:
                continue
            downstream_devices = set(topo_dependents_closure(topo, ev.device_id))
            explained = active_devices & downstream_devices - {ev.device_id}
            correlated = 0
            for other in active:
                if other is ev or other.device_id == ev.device_id:
                    continue
                if ev.correlation and correlation_overlap(ev.correlation, other.correlation):
                    correlated += 1
            own_raises = sum(
                e.raised_count for e in active
                if e.device_id == ev.device_id and e.root_cause
            )
            score = len(explained) * 3 + correlated * 2 + own_raises
            rationale_parts = []
            if explained:
                rationale_parts.append(
                    f"下游 {sorted(explained)} 的告警可由其故障传播解释"
                )
            if correlated:
                rationale_parts.append(f"与 {correlated} 条证据共享关联维度")
            if not rationale_parts:
                rationale_parts.append("底层设备直接故障证据")
            candidates.append(
                RootCauseCandidate(
                    device_id=ev.device_id,
                    score=score,
                    rationale="；".join(rationale_parts),
                    supporting_codes=tuple(sorted(
                        {e.code for e in active if e.device_id == ev.device_id}
                    )),
                    correlated_evidence=correlated,
                )
            )
        candidates.sort(key=lambda c: (-c.score, c.device_id))
        # 同设备去重，保留最高分
        deduped: dict[str, RootCauseCandidate] = {}
        for c in candidates:
            deduped.setdefault(c.device_id, c)
        return list(deduped.values())[:limit]

    def snapshot(self) -> Mapping[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "state": self.state,
            "severity": self.severity.name,
            "created_ts": self.created_ts,
            "updated_ts": self.updated_ts,
            "closed_ts": self.closed_ts,
            "close_reason": self.close_reason,
            "devices": sorted(self.devices),
            "units": sorted(self.units),
            "control_owner": self.control.owner,
            "control_since": self.control.since_ts,
            "control_reason": self.control.reason,
            "active_evidence": [
                {"device": e.device_id, "code": e.code, "since": e.first_ts,
                 "raised_count": e.raised_count}
                for e in self.active_evidence
            ],
            "close_blockers": list(self.close_blockers()),
            "merged_children": list(self.merged_children),
            "merged_into": self.merged_into,
            "signal_seqs": list(self.signal_seqs),
            "escalated": self.escalated,
        }


def topo_dependents_closure(topo, device_id: str) -> tuple[str, ...]:
    from .topology import downstream
    return downstream(topo, device_id)


def correlation_overlap(a: frozenset, b: frozenset) -> bool:
    return bool(a & b)

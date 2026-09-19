"""信号台账与通知历史。

* :class:`SignalLedger` 保存全部原始信号，永不删除；每条信号记录最初归入的
  事件与合并后的最终事件，保证合并后仍可分别追溯。
* :class:`NotificationLog` 记录每一条通知判定（发出或抑制）。抖动窗口内的
  重复告警被抑制；严重度升级强制穿透抑制，立即通知。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .model import Severity, Signal

NOTIFY_SENT = "sent"
NOTIFY_SUPPRESSED = "suppressed"
NOTIFY_ESCALATION = "escalation"


@dataclass
class SignalRecord:
    signal: Signal
    original_incident_id: str | None = None
    final_incident_id: str | None = None
    suppressed_as_duplicate: bool = False
    merged_via: tuple[str, ...] = ()


class SignalLedger:
    def __init__(self) -> None:
        self._seq: list[SignalRecord] = []

    def append(self, sig: Signal) -> SignalRecord:
        rec = SignalRecord(signal=sig)
        self._seq.append(rec)
        return rec

    def all(self) -> tuple[SignalRecord, ...]:
        return tuple(self._seq)

    def by_incident(self, incident_id: str) -> tuple[SignalRecord, ...]:
        return tuple(
            r for r in self._seq
            if r.final_incident_id == incident_id
            or r.original_incident_id == incident_id
        )

    def count(self) -> int:
        return len(self._seq)


@dataclass
class Notification:
    seq: int
    ts: int
    key: str  # 指纹或事件级键
    incident_id: str | None
    channel: str
    level: str  # Severity 名称或事件级别
    title: str
    body: str
    decision: str  # sent | suppressed | escalation
    reason: str
    duplicate_count: int = 0


class NotificationLog:
    """带抖动抑制的通知判定器。

    判定键通常是告警指纹。重复 raise（同一指纹仍在活动期间）落在
    ``dedup_window_ms`` 内则抑制；一旦严重度高于上次已发通知，立即升级通知。
    清除/新事件/事件级通告以 ``force=True`` 穿透。
    """

    def __init__(self) -> None:
        self._items: list[Notification] = []
        self._last_sent: dict[str, tuple[int, Severity]] = {}
        self._dupes: dict[str, int] = {}

    def evaluate(
        self,
        *,
        ts: int,
        key: str,
        window_ms: int,
        severity: Severity,
        title: str,
        body: str,
        incident_id: str | None,
        channel: str = "andon-board",
        active_duplicate: bool = False,
        force: bool = False,
        also_seed: tuple[str, ...] = (),
    ) -> Notification:
        last = self._last_sent.get(key)
        escalation = bool(last and severity > last[1])
        if not force and active_duplicate and last is not None:
            within = ts - last[0] < window_ms
            if within and not escalation:
                self._dupes[key] = self._dupes.get(key, 0) + 1
                n = Notification(
                    seq=len(self._items) + 1, ts=ts, key=key,
                    incident_id=incident_id, channel=channel,
                    level=severity.name, title=title, body=body,
                    decision=NOTIFY_SUPPRESSED,
                    reason=f"抖动窗口 {window_ms}ms 内重复，已累计 "
                           f"{self._dupes[key] + 1} 次",
                    duplicate_count=self._dupes[key] + 1,
                )
                self._items.append(n)
                return n

        decision = NOTIFY_ESCALATION if escalation and not force else NOTIFY_SENT
        reason = "严重度升级，穿透抖动抑制" if escalation else "新告警/事件通告"
        if force and not escalation:
            reason = "事件级强制通告"
        self._last_sent[key] = (ts, severity)
        self._dupes[key] = 0
        # 事件级通告（升级/扩散等）同时为指纹去重键播种，保证下一条重复
        # 立即落入抖动窗口，而不是因通道键不同再发一条
        for seed_key in also_seed:
            self._last_sent[seed_key] = (ts, severity)
            self._dupes.setdefault(seed_key, 0)
        n = Notification(
            seq=len(self._items) + 1, ts=ts, key=key,
            incident_id=incident_id, channel=channel,
            level=severity.name, title=title, body=body,
            decision=decision, reason=reason,
        )
        self._items.append(n)
        return n

    def history(self, incident_id: str | None = None) -> tuple[Notification, ...]:
        if incident_id is None:
            return tuple(self._items)
        return tuple(n for n in self._items if n.incident_id == incident_id)

    def sent(self, incident_id: str | None = None) -> tuple[Notification, ...]:
        return tuple(
            n for n in self.history(incident_id)
            if n.decision in (NOTIFY_SENT, NOTIFY_ESCALATION)
        )

    def suppressed_count(self, incident_id: str | None = None) -> int:
        return sum(
            1 for n in self.history(incident_id)
            if n.decision == NOTIFY_SUPPRESSED
        )

"""安全许可与硬联锁。

自动步骤只有在安全许可有效时才可执行。两类约束相互独立：

* **许可（permit）**：安全系统/安全责任人显式签发的自动操作授权，
  带作用域（全局/单元/设备）与操作类别，可随时撤销，撤销立即生效；
* **联锁（interlock）**：现场硬条件（围栏门、急停、使能缺失），
  联锁存在时无论许可如何一律拒绝。

许可撤销必须能"追上"正在执行的动作：:meth:`allowed` 每次推进都重新求值，
不缓存授权结果。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

ACTION_RESET = "reset"
ACTION_START = "start"
ACTION_GENERIC = "generic"
SCOPE_GLOBAL = "*"


@dataclass(frozen=True)
class Permit:
    key: str  # f"{scope}:{action}"
    scope_type: str  # "global" | "unit" | "device"
    scope: str
    action: str
    granted_ts: int
    revoked_ts: int | None = None
    reason: str = ""
    granted_by: str = "safety-system"

    @property
    def active(self) -> bool:
        return self.revoked_ts is None


@dataclass(frozen=True)
class Interlock:
    scope_type: str
    scope: str
    since_ts: int
    reason: str
    cleared_ts: int | None = None

    @property
    def active(self) -> bool:
        return self.cleared_ts is None


@dataclass(frozen=True)
class PermissionDecision:
    allowed: bool
    reason: str
    matched_permit: str | None = None


class SafetyRegistry:
    def __init__(self) -> None:
        self._permits: list[Permit] = []
        self._interlocks: list[Interlock] = []

    # ---- 许可生命周期 ----
    def grant(self, scope_type: str, scope: str, action: str, ts: int,
              reason: str = "", granted_by: str = "safety-system") -> Permit:
        p = Permit(
            key=f"{scope_type}:{scope}:{action}",
            scope_type=scope_type, scope=scope, action=action,
            granted_ts=ts, reason=reason, granted_by=granted_by,
        )
        self._permits.append(p)
        return p

    def revoke(self, scope_type: str, scope: str, action: str, ts: int,
               reason: str = "安全许可撤销") -> Permit | None:
        """撤销最新一张匹配且仍有效的许可；级联判断由 :meth:`allowed` 完成。"""
        for p in reversed(self._permits):
            if (p.scope_type == scope_type and p.scope == scope
                    and p.action == action and p.active):
                idx = self._permits.index(p)
                revoked = Permit(**{**p.__dict__, "revoked_ts": ts, "reason": reason})
                self._permits[idx] = revoked
                return revoked
        return None

    # ---- 联锁生命周期 ----
    def interlock(self, scope_type: str, scope: str, ts: int, reason: str) -> Interlock:
        il = Interlock(scope_type=scope_type, scope=scope, since_ts=ts, reason=reason)
        self._interlocks.append(il)
        return il

    def clear_interlock(self, scope_type: str, scope: str, reason: str,
                        ts: int) -> Interlock | None:
        for i, il in enumerate(self._interlocks):
            if (il.scope_type == scope_type and il.scope == scope and il.active):
                cleared = Interlock(**{**il.__dict__, "cleared_ts": ts})
                self._interlocks[i] = cleared
                return cleared
        return None

    # ---- 查询 ----
    def active_interlocks(self) -> tuple[Interlock, ...]:
        return tuple(i for i in self._interlocks if i.active)

    def permits_state(self) -> tuple[Permit, ...]:
        return tuple(self._permits)

    def allowed(self, *, device: str, unit: str, action: str, ts: int,
                extra: Mapping[str, str] | None = None) -> PermissionDecision:
        """按当前（ts 时刻）状态判断 device 上的自动动作是否允许。

        联锁优先：任何覆盖该设备的活动联锁直接拒绝。
        许可按特异性匹配：device > unit > global，需要一张在 ts 时仍有效的许可。
        """
        for il in self._interlocks:
            if not il.active or not (il.since_ts <= ts
                                     and (il.cleared_ts is None or il.cleared_ts > ts)):
                continue
            covers = (
                il.scope_type == "global" and il.scope == SCOPE_GLOBAL
                or il.scope_type == "unit" and il.scope == unit
                or il.scope_type == "device" and il.scope == device
            )
            if covers:
                return PermissionDecision(False, f"安全联锁: {il.reason}")

        candidates = []
        for p in self._permits:
            if not (p.granted_ts <= ts and p.active):
                continue
            if p.action != action:
                continue
            covers = (
                p.scope_type == "global" and p.scope == SCOPE_GLOBAL
                or p.scope_type == "unit" and p.scope == unit
                or p.scope_type == "device" and p.scope == device
            )
            if covers:
                specificity = {"device": 3, "unit": 2, "global": 1}[p.scope_type]
                candidates.append((specificity, p))
        if not candidates:
            return PermissionDecision(False, f"无有效安全许可({action})")
        candidates.sort(key=lambda x: x[0], reverse=True)
        best = candidates[0][1]
        return PermissionDecision(True, "许可有效", best.key)

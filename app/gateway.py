"""设备指令网关。

自动步骤不直接触碰设备，统一经网关下发。每条下发获得 ``dispatch_id``，
回调必须携带执行实例与步骤标识（见 README/domain_contract 约束），
网关据此校验回调身份，防止迟到/伪造回调驱动状态。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

DeviceAdapter = Callable[[str, str, Mapping[str, Any]], tuple[bool, str]]


@dataclass(frozen=True)
class DispatchedCommand:
    dispatch_id: str
    incident_id: str
    instance_id: str
    step_id: str
    kind: str  # "action" | "compensation"
    device_id: str
    action: str
    ts: int
    payload: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CommandRecord:
    dispatch_id: str
    ts: int
    device_id: str
    action: str
    accepted: bool
    reason: str


class CommandGateway:
    def __init__(self) -> None:
        self._adapters: dict[str, DeviceAdapter] = {}
        self._pending: dict[str, DispatchedCommand] = {}
        self._resolved: set[str] = set()
        self.log: list[CommandRecord] = []

    def register_adapter(self, device_id: str, adapter: DeviceAdapter) -> None:
        self._adapters[device_id] = adapter

    def send(
        self,
        *,
        dispatch_id: str,
        incident_id: str,
        instance_id: str,
        step_id: str,
        kind: str,
        device_id: str,
        action: str,
        ts: int,
        payload: Mapping[str, Any] | None = None,
    ) -> tuple[bool, str]:
        adapter = self._adapters.get(device_id)
        if adapter is None:
            accepted, reason = True, "网关卡受理，等待异步回调"
        else:
            accepted, reason = adapter(device_id, action, payload or {})
        self.log.append(
            CommandRecord(dispatch_id, ts, device_id, action, accepted, reason)
        )
        if accepted:
            self._pending[dispatch_id] = DispatchedCommand(
                dispatch_id=dispatch_id, incident_id=incident_id,
                instance_id=instance_id, step_id=step_id, kind=kind,
                device_id=device_id, action=action, ts=ts, payload=payload or {},
            )
        return accepted, reason

    def resolve(self, dispatch_id: str) -> DispatchedCommand | None:
        """取出挂起指令；重复/未知回调得到 None。"""
        if dispatch_id in self._resolved:
            return None
        cmd = self._pending.pop(dispatch_id, None)
        if cmd is not None:
            self._resolved.add(dispatch_id)
        return cmd

    def peek(self, dispatch_id: str) -> DispatchedCommand | None:
        return self._pending.get(dispatch_id)

    def pending(self) -> tuple[DispatchedCommand, ...]:
        return tuple(self._pending.values())

    def cancel(self, dispatch_id: str) -> None:
        self._pending.pop(dispatch_id, None)

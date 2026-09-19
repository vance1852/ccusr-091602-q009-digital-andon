"""领域原语：状态枚举、不可变信号、审计事件。

``domain_contract.json`` 中声明的字符串集合在这里以常量形式给出，
启动时可用 :func:`validate_contract` 与契约文件逐项比对，防止实现漂移。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Mapping, Sequence

# ---- 契约中的离散状态（取值必须与 domain_contract.json 一致） ----
INCIDENT_OPEN = "open"
INCIDENT_ACK = "acknowledged"
INCIDENT_MITIGATING = "mitigating"
INCIDENT_MONITORING = "monitoring"
INCIDENT_CLOSED = "closed"
INCIDENT_STATES: tuple[str, ...] = (
    INCIDENT_OPEN,
    INCIDENT_ACK,
    INCIDENT_MITIGATING,
    INCIDENT_MONITORING,
    INCIDENT_CLOSED,
)

STEP_PENDING = "pending"
STEP_RUNNING = "running"
STEP_WAITING = "waiting"
STEP_COMPENSATING = "compensating"
STEP_COMPLETED = "completed"
STEP_FAILED = "failed"
STEP_STATES: tuple[str, ...] = (
    STEP_PENDING,
    STEP_RUNNING,
    STEP_WAITING,
    STEP_COMPENSATING,
    STEP_COMPLETED,
    STEP_FAILED,
)

OWNER_AUTOMATION = "automation"
OWNER_OPERATOR = "operator"
OWNER_SAFETY = "safety"
CONTROL_OWNERS: tuple[str, ...] = (
    OWNER_AUTOMATION,
    OWNER_OPERATOR,
    OWNER_SAFETY,
)

SIGNAL_RAISE = "raise"
SIGNAL_CLEAR = "clear"
SIGNAL_INFO = "info"
SIGNAL_KINDS: tuple[str, ...] = (SIGNAL_RAISE, SIGNAL_CLEAR, SIGNAL_INFO)


class Severity(IntEnum):
    """严重度越高数值越大，升级比较直接用整数。"""

    INFO = 1
    WARNING = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @classmethod
    def parse(cls, value: "Severity | int | str | None") -> "Severity":
        if value is None:
            return Severity.MEDIUM
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return Severity(value)
        return cls[str(value).upper()]


_SEVERITY_TEXT = {
    "info": Severity.INFO,
    "warning": Severity.WARNING,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def severity_value(value: Any) -> Severity:
    if isinstance(value, Severity):
        return value
    if isinstance(value, int):
        return Severity(value)
    return _SEVERITY_TEXT[str(value).lower()]


@dataclass(frozen=True)
class Signal:
    """不可变原始信号。

    信号一经写入全局信号库即不可删除、不可改写——抑制通知、关单、
    合并事件都只改变事件侧的聚合关系，``raw`` 保留上位机原文。
    """

    seq: int
    ts: int
    device_id: str
    code: str
    kind: str
    severity: Severity | None
    fingerprint: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    raw: str = ""


@dataclass(frozen=True)
class AuditEvent:
    """任何人工或自动动作的留痕。"""

    seq: int
    ts: int
    actor: str
    team: str
    action: str
    reason: str
    detail: Mapping[str, Any] = field(default_factory=dict)


def validate_contract(contract: Mapping[str, Any]) -> None:
    """对照 domain_contract.json 校验本实现使用的离散取值。"""
    if tuple(contract["incident_states"]) != INCIDENT_STATES:
        raise ValueError("incident_states 与领域契约不一致")
    if tuple(contract["playbook_steps"]) != STEP_STATES:
        raise ValueError("playbook_steps 与领域契约不一致")
    if tuple(contract["control_owners"]) != CONTROL_OWNERS:
        raise ValueError("control_owners 与领域契约不一致")


# 事件状态机。列表是状态集合而非严格线性流水线：允许 open 直接进入
# mitigating（自动安全停机），monitoring 中复发可回到 mitigating。
_INCIDENT_TRANSITIONS: Mapping[str, Sequence[str]] = {
    INCIDENT_OPEN: (INCIDENT_ACK, INCIDENT_MITIGATING, INCIDENT_CLOSED),
    INCIDENT_ACK: (INCIDENT_MITIGATING, INCIDENT_MONITORING, INCIDENT_CLOSED),
    INCIDENT_MITIGATING: (
        INCIDENT_ACK,
        INCIDENT_MONITORING,
        INCIDENT_CLOSED,
    ),
    INCIDENT_MONITORING: (
        INCIDENT_MITIGATING,
        INCIDENT_ACK,
        INCIDENT_CLOSED,
    ),
    INCIDENT_CLOSED: (),
}


def can_transit(current: str, target: str) -> bool:
    return target in _INCIDENT_TRANSITIONS.get(current, ())

"""领域模型：原始信号、生产事件、处置剧本、通知与审计记录。

所有模型均为纯数据对象；状态推进规则集中在 app.orchestrator 中。
状态取值与 domain_contract.json 保持一致（见 tests/test_contract_alignment.py）。
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional


class Severity(enum.IntEnum):
    """告警严重度，数值越大越严重，用于升级判定。"""

    INFO = 10
    WARNING = 20
    MAJOR = 30
    CRITICAL = 40

    @classmethod
    def parse(cls, raw: str) -> "Severity":
        try:
            return cls[raw.strip().upper()]
        except KeyError:
            raise ValueError(f"未知严重度: {raw!r}") from None

    @property
    def label(self) -> str:
        return self.name.lower()


class SignalKind(str, enum.Enum):
    FAULT = "fault"
    RECOVERY = "recovery"


class IncidentState(str, enum.Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    MITIGATING = "mitigating"
    MONITORING = "monitoring"
    CLOSED = "closed"


class StepState(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    WAITING = "waiting"
    COMPENSATING = "compensating"
    COMPLETED = "completed"
    FAILED = "failed"


class ControlOwner(str, enum.Enum):
    AUTOMATION = "automation"
    OPERATOR = "operator"
    SAFETY = "safety"


@dataclass(frozen=True)
class Signal:
    """一条原始告警信号。

    无论后续如何归并、抑制通知或结案，信号本身都不会被删除，
    始终可以通过事件追溯到每一条原始记录。
    """

    id: str
    alarm_code: str
    device: str
    unit: str
    kind: SignalKind
    severity: Severity
    incident_type: str
    correlation_group: str
    role: str  # root | symptom
    occurred_at: float
    received_at: float
    evidence_key: Optional[str]
    payload: dict = field(default_factory=dict)


@dataclass
class Evidence:
    """一条仍被信号支撑的活跃证据；恢复信号只能清除与自己同键的证据。"""

    key: str
    device: str
    unit: str
    alarm_code: str
    severity: Severity
    role: str
    opened_at: float
    signal_id: str


@dataclass
class StepInstance:
    """剧本步骤的一次运行实例。"""

    step_id: str
    name: str
    kind: str  # automatic | manual
    action: Optional[str]
    requires_permit: bool
    timeout_seconds: Optional[float]
    preconditions: tuple
    compensation: Optional[dict]
    state: StepState = StepState.PENDING
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    execution_id: Optional[str] = None
    retired_execution_ids: list = field(default_factory=list)
    blocked_reason: Optional[str] = None
    failure_reason: Optional[str] = None
    held: bool = False
    compensation_record: Optional[dict] = None


@dataclass
class PlaybookInstance:
    """绑定在某个事件上的一次剧本执行。"""

    id: str
    playbook_id: str
    incident_id: str
    permit_scope: Optional[str]
    steps: list
    started_at: float
    status: str = "active"  # active | completed | halted | closed


@dataclass
class Incident:
    """有边界的生产事件：按关联组 + 时间窗归并，结案后不再吸收新信号。"""

    id: str
    incident_type: str
    correlation_group: str
    created_at: float
    topology_version: str
    state: IncidentState = IncidentState.OPEN
    severity: Severity = Severity.INFO
    max_severity: Severity = Severity.INFO
    last_signal_at: float = 0.0
    evidence: dict = field(default_factory=dict)
    signal_ids: list = field(default_factory=list)
    control_owner: ControlOwner = ControlOwner.AUTOMATION
    assigned_to: Optional[str] = None
    paused: bool = False
    merged_into: Optional[str] = None
    linked_children: list = field(default_factory=list)
    playbook: Optional[PlaybookInstance] = None


@dataclass(frozen=True)
class Notification:
    """一条通知记录；被抑制的通知也保留（status=suppressed）。"""

    id: str
    incident_id: str
    kind: str
    severity: Severity
    at: float
    status: str  # sent | suppressed
    message: str
    reason: Optional[str] = None


@dataclass(frozen=True)
class AuditEntry:
    """一条审计留痕：谁、哪个班组、做了什么、为什么。"""

    id: str
    at: float
    incident_id: Optional[str]
    actor: str
    shift: Optional[str]
    action: str
    reason: Optional[str]
    details: dict = field(default_factory=dict)


@dataclass
class Permit:
    """安全许可：自动步骤只有在其作用域许可有效时才能执行。"""

    permit_id: str
    scope: str
    granted_by: str
    valid_from: float
    valid_to: float
    revoked: bool = False
    revoke_reason: Optional[str] = None

    def valid(self, now: float) -> bool:
        return (not self.revoked) and self.valid_from <= now <= self.valid_to


@dataclass(frozen=True)
class CallbackResult:
    """自动回调的受理结果；被拒绝的回调只留痕、不生效。"""

    accepted: bool
    reason: str

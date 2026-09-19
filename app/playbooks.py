"""处置剧本定义与运行时状态。

每个事件类型可绑定一个剧本；剧本由有序步骤组成，步骤可以是：

* ``auto``：由编排器下发设备指令，必须有当前有效的安全许可；
* ``manual``：等待值守员完成并回填。

自动步骤带：

* ``precondition``：前置条件谓词名，不满足时步骤停在 ``waiting``，
  每次 tick 重新求值（条件可能随证据恢复/许可签发而变化）；
* ``timeout_ms``：下发后超时未回调则进入补偿；
* ``compensation``：补偿动作，补偿自身也是受控自动动作，无许可时
  停在 ``compensating`` 并升级通知，绝不在不安全状态下"将错就错"。

步骤状态取值严格对应 domain_contract.json 的 playbook_steps。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from .model import (
    STEP_COMPENSATING,
    STEP_COMPLETED,
    STEP_FAILED,
    STEP_PENDING,
    STEP_RUNNING,
    STEP_WAITING,
)

MODE_AUTO = "auto"
MODE_MANUAL = "manual"
ON_TIMEOUT_COMPENSATE = "compensate"
ON_TIMEOUT_FAIL = "fail"


@dataclass(frozen=True)
class StepDef:
    step_id: str
    name: str
    mode: str
    action: str | None = None
    permit_action: str = "generic"
    # 目标选择：root_cause(评分第一的候选) | first_evidence | "<device_id>"
    target: str = "first_evidence"
    preconditions: tuple[str, ...] = ()
    timeout_ms: int | None = None
    on_timeout: str = ON_TIMEOUT_COMPENSATE
    compensation: str | None = None
    comp_permit_action: str = "generic"
    description: str = ""


@dataclass(frozen=True)
class PlaybookDef:
    playbook_id: str
    incident_type: str
    name: str
    steps: tuple[StepDef, ...]
    auto_arm: bool = True


@dataclass
class StepRun:
    step_id: str
    state: str = STEP_PENDING
    attempts: int = 0
    dispatch_id: str | None = None
    dispatched_ts: int | None = None
    deadline_ts: int | None = None
    finished_ts: int | None = None
    wait_reason: str = ""
    log: list[tuple[int, str, str]] = field(default_factory=list)

    def note(self, ts: int, event: str, detail: str = "") -> None:
        self.log.append((ts, event, detail))


class PlaybookInstance:
    """剧本执行实例。状态迁移方法只改状态，安全裁决由 engine 完成。"""

    def __init__(self, instance_id: str, incident_id: str,
                 definition: PlaybookDef, ts: int):
        self.instance_id = instance_id
        self.incident_id = incident_id
        self.def_id = definition.playbook_id
        self.definition = definition
        self.created_ts = ts
        self.updated_ts = ts
        self.status = "armed"  # armed | active | paused | completed | failed
        self.steps: dict[str, StepRun] = {
            s.step_id: StepRun(s.step_id) for s in definition.steps
        }
        self.order: tuple[str, ...] = tuple(s.step_id for s in definition.steps)
        self.cursor = 0  # 当前待推进步骤下标
        self.paused: bool = False
        self.pause_reason = ""

    # ---- 查询 ----
    @property
    def current(self) -> StepDef | None:
        if self.cursor >= len(self.definition.steps):
            return None
        return self.definition.steps[self.cursor]

    @property
    def current_run(self) -> StepRun | None:
        s = self.current
        return None if s is None else self.steps[s.step_id]

    def run_of(self, step_id: str) -> StepRun:
        return self.steps[step_id]

    def is_done(self) -> bool:
        return self.cursor >= len(self.definition.steps)

    def stuck_steps(self) -> tuple[Mapping[str, Any], ...]:
        """卡住的步骤：running 已到/超时限、waiting 等条件、compensating 等许可。"""
        out: list[Mapping[str, Any]] = []
        for sid in self.order:
            run = self.steps[sid]
            if run.state in (STEP_WAITING, STEP_COMPENSATING):
                out.append({
                    "step_id": sid, "state": run.state,
                    "reason": run.wait_reason or "等待前置条件/许可",
                })
            elif run.state == STEP_FAILED:
                out.append({
                    "step_id": sid, "state": run.state,
                    "reason": run.wait_reason or "步骤失败",
                })
        return tuple(out)

    # ---- 迁移 ----
    def activate(self, ts: int) -> None:
        self.status = "active"
        self.updated_ts = ts

    def mark_waiting(self, run: StepRun, ts: int, reason: str) -> None:
        run.state = STEP_WAITING
        run.wait_reason = reason
        run.note(ts, "waiting", reason)
        self.updated_ts = ts

    def mark_running(self, run: StepRun, ts: int, dispatch_id: str,
                     timeout_ms: int | None) -> None:
        run.state = STEP_RUNNING
        run.attempts += 1
        run.dispatch_id = dispatch_id
        run.dispatched_ts = ts
        run.deadline_ts = ts + timeout_ms if timeout_ms is not None else None
        run.wait_reason = ""
        run.note(ts, "dispatched", dispatch_id)
        self.updated_ts = ts

    def mark_completed(self, run: StepRun, ts: int, detail: str = "") -> None:
        run.state = STEP_COMPLETED
        run.finished_ts = ts
        run.wait_reason = ""
        run.note(ts, "completed", detail)
        self.cursor += 1
        self.updated_ts = ts
        if self.is_done():
            self.status = "completed"

    def begin_compensation(self, run: StepRun, ts: int, reason: str) -> None:
        run.state = STEP_COMPENSATING
        run.wait_reason = reason
        run.note(ts, "compensating", reason)
        self.updated_ts = ts

    def hold_compensation(self, run: StepRun, ts: int, reason: str) -> None:
        """补偿已判定必须执行但安全条件不满足：停在 compensating 等许可。"""
        run.state = STEP_COMPENSATING
        run.wait_reason = reason
        run.note(ts, "compensation-blocked", reason)
        self.updated_ts = ts

    def mark_failed(self, run: StepRun, ts: int, reason: str) -> None:
        run.state = STEP_FAILED
        run.wait_reason = reason
        run.note(ts, "failed", reason)
        self.status = "failed"
        self.updated_ts = ts

    def pause(self, ts: int, reason: str) -> None:
        self.paused = True
        self.status = "paused"
        self.pause_reason = reason
        run = self.current_run
        if run is not None and run.state == STEP_RUNNING:
            run.note(ts, "paused-midflight", reason)
        self.updated_ts = ts

    def resume(self, ts: int) -> None:
        self.paused = False
        self.status = "active" if not self.is_done() else "completed"
        self.pause_reason = ""
        self.updated_ts = ts

    def snapshot(self) -> Mapping[str, Any]:
        return {
            "instance_id": self.instance_id,
            "incident_id": self.incident_id,
            "playbook_id": self.def_id,
            "status": self.status,
            "paused": self.paused,
            "cursor": self.cursor,
            "current_step": None if self.current is None else self.current.step_id,
            "steps": [
                {"step_id": sid, "state": self.steps[sid].state,
                 "attempts": self.steps[sid].attempts,
                 "dispatch_id": self.steps[sid].dispatch_id,
                 "deadline_ts": self.steps[sid].deadline_ts,
                 "note": self.steps[sid].wait_reason}
                for sid in self.order
            ],
            "stuck": list(self.stuck_steps()),
        }


class PlaybookLibrary:
    def __init__(self, defs: Mapping[str, PlaybookDef]):
        self._defs = defs

    def get(self, playbook_id: str) -> PlaybookDef:
        if playbook_id not in self._defs:
            raise KeyError(f"未知剧本: {playbook_id}")
        return self._defs[playbook_id]

    def for_incident_type(self, incident_type: str) -> PlaybookDef | None:
        for d in self._defs.values():
            if d.incident_type == incident_type:
                return d
        return None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PlaybookLibrary":
        defs: dict[str, PlaybookDef] = {}
        for pb in data["playbooks"]:
            steps: list[StepDef] = []
            for s in pb.get("steps", []):
                raw_pre = s.get("preconditions", s.get("precondition", ()))
                if isinstance(raw_pre, str):
                    preconditions = (raw_pre,)
                else:
                    preconditions = tuple(raw_pre)
                steps.append(
                    StepDef(
                        step_id=s["id"],
                        name=s.get("name", s["id"]),
                        mode=s.get("mode", MODE_AUTO),
                        action=s.get("action"),
                        permit_action=s.get("permit_action", "generic"),
                        target=s.get("target", "first_evidence"),
                        preconditions=preconditions,
                        timeout_ms=s.get("timeout_ms"),
                        on_timeout=s.get("on_timeout", ON_TIMEOUT_COMPENSATE),
                        compensation=s.get("compensation"),
                        comp_permit_action=s.get("comp_permit_action", "generic"),
                        description=s.get("description", ""),
                    )
                )
            d = PlaybookDef(
                playbook_id=pb["id"],
                incident_type=pb["incident_type"],
                name=pb.get("name", pb["id"]),
                steps=tuple(steps),
                auto_arm=bool(pb.get("auto_arm", True)),
            )
            defs[d.playbook_id] = d
        return cls(defs)

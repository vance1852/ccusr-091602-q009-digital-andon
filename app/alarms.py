"""告警映射：原始代码 -> 规范化事件类型 / 严重度 / 归并与去重策略。

映射数据来自仓库 ``data/alarms.json``。一条映射声明：

* ``incident_type``：归入哪类生产事件；
* ``group_by``：从信号 payload 中取哪些键做跨设备关联（如同一个轴）；
* ``root_cause``：该代码是否可作为根因候选；
* ``dedup_window_ms``：短时抖动窗口，窗口内同指纹的重复 raise 只在事件上
  累加出现次数，不重复通知（严重度升级由通知层强制穿透）；
* ``clearance_for``：清除信号代码可以抵消哪些 raise 代码。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from .model import Severity, severity_value

DEFAULT_DEDUP_WINDOW_MS = 5_000


@dataclass(frozen=True)
class AlarmDef:
    code: str
    incident_type: str
    default_severity: Severity
    group_by: tuple[str, ...] = ()
    root_cause: bool = True
    dedup_window_ms: int = DEFAULT_DEDUP_WINDOW_MS
    playbook: str | None = None
    clearance_for: tuple[str, ...] = ()
    title: str = ""
    notify: bool = True
    meta: Mapping[str, object] = field(default_factory=dict)


class AlarmMap:
    def __init__(self, defs: Mapping[str, AlarmDef], default_window: int):
        self._defs = defs
        self.default_window = default_window

    def get(self, code: str) -> AlarmDef | None:
        return self._defs.get(code)

    def require(self, code: str) -> AlarmDef:
        d = self._defs.get(code)
        if d is None:
            raise KeyError(f"未登记的告警代码: {code}")
        return d

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "AlarmMap":
        default_window = int(data.get("defaults", {}).get("dedup_window_ms",
                                                          DEFAULT_DEDUP_WINDOW_MS))
        defs: dict[str, AlarmDef] = {}
        for a in data["alarms"]:
            code = str(a["code"])
            clearance = tuple(a.get("clearance_for", ()))
            defs[code] = AlarmDef(
                code=code,
                incident_type=str(a["incident_type"]),
                default_severity=severity_value(a.get("severity", "medium")),
                group_by=tuple(a.get("group_by", ())),
                root_cause=bool(a.get("root_cause", True)),
                dedup_window_ms=int(a.get("dedup_window_ms", default_window)),
                playbook=a.get("playbook"),
                clearance_for=clearance,
                title=str(a.get("title", code)),
                notify=bool(a.get("notify", True)),
                meta=dict(a.get("meta", {})),
            )
        return cls(defs, default_window)


def correlation_values(d: AlarmDef, payload: Mapping[str, Any]) -> tuple[tuple[str, str], ...]:
    """提取跨设备关联键值，如 (("axis", "X1"),)。缺失的键不产生关联。"""
    vals: list[tuple[str, str]] = []
    for key in d.group_by:
        if key in payload and payload[key] is not None:
            vals.append((key, str(payload[key])))
    return tuple(vals)

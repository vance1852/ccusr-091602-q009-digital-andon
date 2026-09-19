"""装载仓库给出的设备依赖拓扑、告警映射与处置剧本。

三类配置都带生效版本：拓扑版本会烙印在事件上，便于事后追溯当时
使用的是哪一版依赖关系。装载时做严格校验，配置错误尽早暴露。
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .models import Severity, SignalKind


class ConfigError(ValueError):
    """配置文件缺少必填字段或引用不一致。"""


@dataclass(frozen=True)
class Device:
    id: str
    unit: str
    depends_on: tuple


@dataclass(frozen=True)
class Topology:
    """设备依赖图（带生效版本）。"""

    version: str
    effective_from: str
    units: dict
    devices: dict

    def is_ancestor(self, maybe_ancestor: str, device: str) -> bool:
        """maybe_ancestor 是否为 device 的（传递）上游依赖。"""
        seen = set()
        stack = [device]
        while stack:
            cur = stack.pop()
            if cur == maybe_ancestor:
                return True
            if cur in seen:
                continue
            seen.add(cur)
            node = self.devices.get(cur)
            if node:
                stack.extend(node.depends_on)
        return False


@dataclass(frozen=True)
class AlarmMapping:
    """告警码 → 设备 / 严重度 / 事件类型 / 关联组 的映射。"""

    code: str
    device: str
    kind: SignalKind
    severity: Severity
    incident_type: str
    correlation_group: str
    role: str  # root | symptom
    clears: Optional[str] = None

    @property
    def evidence_key(self) -> str:
        """故障与恢复信号共享同一证据键，恢复才能精确清除对应故障。"""
        base = self.clears if self.kind is SignalKind.RECOVERY else self.code
        return f"{self.device}:{base}"


@dataclass(frozen=True)
class StepDef:
    step_id: str
    name: str
    kind: str  # automatic | manual
    action: Optional[str]
    requires_permit: bool
    timeout_seconds: Optional[float]
    preconditions: tuple
    compensation: Optional[dict]


@dataclass(frozen=True)
class PlaybookDef:
    playbook_id: str
    incident_type: str
    permit_scope: Optional[str]
    steps: tuple


def _read_json(path: Path) -> dict:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"配置文件不存在: {path}") from None
    except json.JSONDecodeError as exc:
        raise ConfigError(f"配置文件不是合法 JSON: {path}: {exc}") from None


def _require(mapping: dict, key: str, where: str):
    if key not in mapping:
        raise ConfigError(f"{where} 缺少必填字段 {key!r}")
    return mapping[key]


def load_topology(path) -> Topology:
    raw = _read_json(Path(path))
    version = _require(raw, "version", "topology")
    effective_from = _require(raw, "effective_from", "topology")
    units = {}
    for entry in _require(raw, "units", "topology"):
        uid = _require(entry, "id", "topology.units[]")
        units[uid] = entry.get("name", uid)
    devices = {}
    for entry in _require(raw, "devices", "topology"):
        did = _require(entry, "id", "topology.devices[]")
        unit = _require(entry, "unit", f"topology.devices[{did}]")
        if unit not in units:
            raise ConfigError(f"设备 {did} 引用了未知单元 {unit}")
        deps = tuple(entry.get("depends_on", []))
        devices[did] = Device(id=did, unit=unit, depends_on=deps)
    for dev in devices.values():
        for dep in dev.depends_on:
            if dep not in devices:
                raise ConfigError(f"设备 {dev.id} 依赖了未知设备 {dep}")
    return Topology(version=version, effective_from=effective_from, units=units, devices=devices)


def load_alarm_map(path, topology: Topology) -> dict:
    raw = _read_json(Path(path))
    _require(raw, "version", "alarm_map")
    table = _require(raw, "alarms", "alarm_map")
    mappings = {}
    for code, entry in table.items():
        device = _require(entry, "device", f"alarm_map[{code}]")
        if device not in topology.devices:
            raise ConfigError(f"告警 {code} 引用了拓扑中不存在的设备 {device}")
        kind = SignalKind(_require(entry, "kind", f"alarm_map[{code}]"))
        clears = entry.get("clears")
        if kind is SignalKind.RECOVERY:
            if not clears:
                raise ConfigError(f"恢复类告警 {code} 必须声明 clears")
            target = table.get(clears)
            if target is None:
                raise ConfigError(f"恢复类告警 {code} 的 clears 指向未知告警 {clears}")
            if target.get("kind") != "fault":
                raise ConfigError(f"恢复类告警 {code} 的 clears 必须指向故障类告警")
            if target.get("device") != device:
                raise ConfigError(f"恢复类告警 {code} 与清除目标 {clears} 不在同一设备")
        mappings[code] = AlarmMapping(
            code=code,
            device=device,
            kind=kind,
            severity=Severity.parse(_require(entry, "severity", f"alarm_map[{code}]")),
            incident_type=_require(entry, "incident_type", f"alarm_map[{code}]"),
            correlation_group=_require(entry, "correlation_group", f"alarm_map[{code}]"),
            role=entry.get("role", "symptom"),
            clears=clears,
        )
    return mappings


def load_playbooks(path) -> dict:
    raw = _read_json(Path(path))
    _require(raw, "version", "playbooks")
    table = _require(raw, "playbooks", "playbooks")
    defs = {}
    for incident_type, entry in table.items():
        steps = []
        seen_ids = set()
        for raw_step in _require(entry, "steps", f"playbooks[{incident_type}]"):
            sid = _require(raw_step, "id", f"playbooks[{incident_type}].steps[]")
            if sid in seen_ids:
                raise ConfigError(f"剧本 {incident_type} 的步骤 id 重复: {sid}")
            seen_ids.add(sid)
            kind = _require(raw_step, "kind", f"playbooks[{incident_type}].steps[{sid}]")
            if kind not in ("automatic", "manual"):
                raise ConfigError(f"步骤 {sid} 的 kind 必须是 automatic 或 manual")
            steps.append(
                StepDef(
                    step_id=sid,
                    name=raw_step.get("name", sid),
                    kind=kind,
                    action=raw_step.get("action"),
                    requires_permit=bool(raw_step.get("requires_permit", False)),
                    timeout_seconds=raw_step.get("timeout_seconds"),
                    preconditions=tuple(raw_step.get("preconditions", [])),
                    compensation=raw_step.get("compensation"),
                )
            )
        defs[incident_type] = PlaybookDef(
            playbook_id=_require(entry, "playbook_id", f"playbooks[{incident_type}]"),
            incident_type=incident_type,
            permit_scope=entry.get("permit_scope"),
            steps=tuple(steps),
        )
    return defs

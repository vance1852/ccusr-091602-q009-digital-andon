"""版本化设备依赖拓扑。

设备依赖关系有生效版本（见 README）：查询影响面时按信号时间戳选择当时
生效的拓扑版本，事后回灌的历史信号不会被今天的拓扑错误归并。

拓扑是有向图 ``depends_on``：A 依赖 B（A 的运行需要 B 正常），因此 B 故障
会向上游传播到 A。``downstream`` 在加载时反向索引得到。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence


@dataclass(frozen=True)
class Device:
    device_id: str
    name: str
    unit: str
    kind: str
    depends_on: tuple[str, ...] = ()
    # 该设备故障是否可能成为其他设备告警的根因候选
    root_cause_eligible: bool = True
    meta: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class TopologyVersion:
    version: str
    effective_from: int  # 含起点，毫秒时间戳
    devices: Mapping[str, Device]
    _dependents: Mapping[str, tuple[str, ...]]


class Topology:
    """带版本的设备依赖库。"""

    def __init__(self, versions: Sequence[TopologyVersion]):
        if not versions:
            raise ValueError("至少需要一个拓扑版本")
        self._versions = tuple(sorted(versions, key=lambda v: v.effective_from))

    def version_at(self, ts: int) -> TopologyVersion:
        """返回 ts 时刻生效的最新版本。"""
        chosen = self._versions[0]
        for v in self._versions:
            if v.effective_from <= ts:
                chosen = v
            else:
                break
        return chosen

    def current(self) -> TopologyVersion:
        return self._versions[-1]

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "Topology":
        versions: list[TopologyVersion] = []
        for block in data["versions"]:
            devices: dict[str, Device] = {}
            dependents: dict[str, list[str]] = {}
            for d in block["devices"]:
                deps = tuple(d.get("depends_on", ()))
                devices[d["id"]] = Device(
                    device_id=d["id"],
                    name=d.get("name", d["id"]),
                    unit=d.get("unit", "unknown"),
                    kind=d.get("kind", "device"),
                    depends_on=deps,
                    root_cause_eligible=bool(d.get("root_cause_eligible", True)),
                    meta=dict(d.get("meta", {})),
                )
                dependents.setdefault(d["id"], [])
            for dev in devices.values():
                for dep in dev.depends_on:
                    if dep not in devices:
                        raise ValueError(
                            f"拓扑 {block['version']}: {dev.device_id} 依赖未知设备 {dep}"
                        )
                    dependents[dep].append(dev.device_id)
            frozen_dependents = {k: tuple(sorted(v)) for k, v in dependents.items()}
            versions.append(
                TopologyVersion(
                    version=block["version"],
                    effective_from=int(block["effective_from"]),
                    devices=devices,
                    _dependents=frozen_dependents,
                )
            )
        return cls(versions)


def downstream(topo: TopologyVersion, device_id: str) -> tuple[str, ...]:
    """返回依赖 device_id 的全部设备（BFS 传递闭包，含自身）。"""
    seen: set[str] = set()
    order: list[str] = []
    queue = [device_id]
    while queue:
        cur = queue.pop(0)
        if cur in seen:
            continue
        seen.add(cur)
        order.append(cur)
        for child in topo._dependents.get(cur, ()):
            if child not in seen:
                queue.append(child)
    return tuple(order)


def upstream_chain(topo: TopologyVersion, device_id: str) -> tuple[str, ...]:
    """返回 device_id 依赖链上的全部设备（含自身），沿 depends_on 上行。"""
    seen: set[str] = set()
    order: list[str] = []
    queue = [device_id]
    while queue:
        cur = queue.pop(0)
        if cur in seen:
            continue
        seen.add(cur)
        order.append(cur)
        dev = topo.devices.get(cur)
        if dev is not None:
            for dep in dev.depends_on:
                if dep not in seen:
                    queue.append(dep)
    return tuple(order)


def impacted_units(topo: TopologyVersion, device_ids: Sequence[str]) -> tuple[str, ...]:
    units = {
        topo.devices[d].unit
        for d in device_ids
        if d in topo.devices
    }
    return tuple(sorted(units))

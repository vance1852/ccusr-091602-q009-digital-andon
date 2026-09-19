"""从仓库数据文件装配引擎。"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from .alarms import AlarmMap
from .engine import OrchestrationEngine
from .model import validate_contract
from .playbooks import PlaybookLibrary
from .safety import SafetyRegistry
from .topology import Topology

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"
CONTRACT_PATH = REPO_ROOT / "domain_contract.json"


def load_json(path: Path) -> Mapping[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def build_engine(data_dir: Path | None = None,
                 *, validate: bool = True,
                 auto_close_grace_ms: int = 30_000) -> OrchestrationEngine:
    data_dir = data_dir or DATA_DIR
    topology = Topology.from_dict(load_json(data_dir / "devices.json"))
    alarm_map = AlarmMap.from_dict(load_json(data_dir / "alarms.json"))
    playbooks = PlaybookLibrary.from_dict(load_json(data_dir / "playbooks.json"))
    if validate:
        validate_contract(load_json(CONTRACT_PATH))
    return OrchestrationEngine(
        topology, alarm_map, playbooks, SafetyRegistry(),
        auto_close_grace_ms=auto_close_grace_ms,
    )

"""领域枚举必须与仓库给出的 domain_contract.json 完全一致。"""

import json
import unittest
from pathlib import Path

from app import ControlOwner, IncidentState, StepState


class ContractAlignmentTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = json.loads(Path("domain_contract.json").read_text(encoding="utf-8"))

    def test_incident_states_match_contract(self):
        self.assertEqual([s.value for s in IncidentState], self.contract["incident_states"])

    def test_playbook_step_states_match_contract(self):
        self.assertEqual([s.value for s in StepState], self.contract["playbook_steps"])

    def test_control_owners_match_contract(self):
        self.assertEqual([o.value for o in ControlOwner], self.contract["control_owners"])


if __name__ == "__main__":
    unittest.main()

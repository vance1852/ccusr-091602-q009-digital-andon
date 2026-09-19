"""归并：交错告警归入同一有边界事件，原始信号全保留，根因候选可解释。"""

import unittest

from app import ManualClock, Orchestrator


def make_orchestrator(start=1_000.0):
    clock = ManualClock(start)
    return Orchestrator.from_config_dir(clock=clock), clock


class CorrelationTest(unittest.TestCase):
    def test_interleaved_alarms_collapse_into_one_incident(self):
        orch, clock = make_orchestrator()
        orch.ingest("DRV_OVERCURRENT")
        for _ in range(50):
            clock.advance(0.5)
            orch.ingest("RBT_STALL")
            orch.ingest("CNV_JAM")
            orch.ingest("VIS_REJECT")
        incidents = orch.list_incidents()
        self.assertEqual(len(incidents), 1)
        view = orch.operations_view(incidents[0]["id"])
        # 1 条驱动告警 + 150 条下游症状，全部保留。
        self.assertEqual(view["signal_count"], 151)
        self.assertEqual(view["state"], "mitigating")

    def test_root_cause_candidate_is_upstream_drive(self):
        orch, clock = make_orchestrator()
        orch.ingest("RBT_STALL")
        clock.advance(1)
        orch.ingest("CNV_JAM")
        clock.advance(1)
        orch.ingest("DRV_OVERCURRENT")
        clock.advance(1)
        orch.ingest("VIS_REJECT")
        view = orch.operations_view(orch.list_incidents()[0]["id"])
        top = view["root_cause_candidates"][0]
        self.assertEqual(top["device"], "DRV-101")
        self.assertIn("上游", top["rationale"])
        self.assertTrue(top["active"])

    def test_affected_units_cover_all_three_stations(self):
        orch, clock = make_orchestrator()
        orch.ingest("DRV_OVERCURRENT")
        clock.advance(1)
        orch.ingest("RBT_STALL")
        clock.advance(1)
        orch.ingest("VIS_REJECT")
        view = orch.operations_view(orch.list_incidents()[0]["id"])
        units = {u["unit"] for u in view["affected_units"]}
        self.assertEqual(units, {"UNIT-CONV", "UNIT-ROBOT", "UNIT-VISION"})

    def test_incident_is_bounded_by_correlation_window(self):
        orch, clock = make_orchestrator()
        orch.ingest("DRV_OVERCURRENT")
        clock.advance(301)  # 超过 300 秒关联窗
        orch.ingest("DRV_OVERCURRENT")
        self.assertEqual(len(orch.list_incidents()), 2)

    def test_closed_incident_does_not_absorb_new_signals(self):
        orch, clock = make_orchestrator()
        orch.ingest("DRV_OVERCURRENT")
        clock.advance(1)
        orch.ingest("DRV_OVERCURRENT_CLR")
        inc_id = orch.list_incidents()[0]["id"]
        orch.close(inc_id, operator="张三", shift="甲班", reason="故障已排除")
        clock.advance(2)
        orch.ingest("DRV_OVERCURRENT")
        incidents = orch.list_incidents()
        self.assertEqual(len(incidents), 2)
        states = {i["id"]: i["state"] for i in incidents}
        self.assertEqual(states[inc_id], "closed")

    def test_unknown_alarm_code_rejected(self):
        orch, _ = make_orchestrator()
        with self.assertRaises(Exception):
            orch.ingest("NO_SUCH_ALARM")


if __name__ == "__main__":
    unittest.main()

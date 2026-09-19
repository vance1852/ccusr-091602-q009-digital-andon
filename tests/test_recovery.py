"""恢复语义：恢复信号只清除自己的证据，不得关闭仍被其他证据支撑的事件。"""

import unittest

from app import ManualClock, Orchestrator


def make_orchestrator(start=1_000.0):
    clock = ManualClock(start)
    return Orchestrator.from_config_dir(clock=clock), clock


class RecoverySemanticsTest(unittest.TestCase):
    def test_partial_recovery_does_not_close_incident(self):
        orch, clock = make_orchestrator()
        orch.grant_permit("P-1", "UNIT-CONV", granted_by="安全员", valid_from=0, valid_to=10_000)
        orch.ingest("DRV_OVERCURRENT")
        clock.advance(1)
        orch.ingest("RBT_STALL")
        clock.advance(1)
        orch.ingest("DRV_OVERCURRENT_CLR")  # 驱动恢复，但机器人停顿证据仍在
        inc_id = orch.list_incidents()[0]["id"]
        view = orch.operations_view(inc_id)
        self.assertNotEqual(view["state"], "monitoring")
        self.assertNotEqual(view["state"], "closed")
        remaining = {e["key"] for e in view["active_evidence"]}
        self.assertEqual(remaining, {"RBT-301:RBT_STALL"})

    def test_full_recovery_moves_to_monitoring_not_closed(self):
        orch, clock = make_orchestrator()
        orch.grant_permit("P-1", "UNIT-CONV", granted_by="安全员", valid_from=0, valid_to=10_000)
        orch.ingest("DRV_OVERCURRENT")
        clock.advance(1)
        orch.ingest("RBT_STALL")
        clock.advance(1)
        orch.ingest("DRV_OVERCURRENT_CLR")
        clock.advance(1)
        orch.ingest("RBT_STALL_CLR")
        inc_id = orch.list_incidents()[0]["id"]
        view = orch.operations_view(inc_id)
        self.assertEqual(view["state"], "monitoring")  # 结案只能由值守员执行
        self.assertEqual(view["active_evidence"], [])

    def test_late_or_duplicate_recovery_only_leaves_trace(self):
        orch, clock = make_orchestrator()
        orch.grant_permit("P-1", "UNIT-CONV", granted_by="安全员", valid_from=0, valid_to=10_000)
        orch.ingest("DRV_OVERCURRENT")
        clock.advance(1)
        orch.ingest("DRV_OVERCURRENT_CLR")
        clock.advance(1)
        orch.ingest("DRV_OVERCURRENT_CLR")  # 重复恢复：证据已清
        inc_id = orch.list_incidents()[0]["id"]
        view = orch.operations_view(inc_id)
        self.assertEqual(view["state"], "monitoring")
        late = [a for a in view["audit"] if a["action"] == "late_recovery"]
        self.assertEqual(len(late), 1)
        # 信号仍挂在事件上，可追溯。
        self.assertEqual(view["signal_count"], 3)

    def test_recovery_after_close_does_not_reopen(self):
        orch, clock = make_orchestrator()
        orch.grant_permit("P-1", "UNIT-CONV", granted_by="安全员", valid_from=0, valid_to=10_000)
        orch.ingest("DRV_OVERCURRENT")
        clock.advance(1)
        orch.ingest("DRV_OVERCURRENT_CLR")
        inc_id = orch.list_incidents()[0]["id"]
        orch.close(inc_id, operator="张三", shift="甲班", reason="确认恢复")
        clock.advance(5)
        orch.ingest("DRV_OVERCURRENT_CLR")  # 迟到的恢复
        view = orch.operations_view(inc_id)
        self.assertEqual(view["state"], "closed")
        self.assertEqual(len([a for a in view["audit"] if a["action"] == "late_recovery"]), 1)

    def test_new_fault_during_monitoring_reopens_incident(self):
        orch, clock = make_orchestrator()
        orch.grant_permit("P-1", "UNIT-CONV", granted_by="安全员", valid_from=0, valid_to=10_000)
        orch.ingest("DRV_OVERCURRENT")
        clock.advance(1)
        orch.ingest("DRV_OVERCURRENT_CLR")
        inc_id = orch.list_incidents()[0]["id"]
        clock.advance(2)
        orch.ingest("CNV_JAM")
        view = orch.operations_view(inc_id)
        self.assertEqual(view["state"], "open")
        self.assertEqual(len(orch.list_incidents()), 1)


if __name__ == "__main__":
    unittest.main()

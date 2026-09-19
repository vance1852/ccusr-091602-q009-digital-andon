"""通知策略：短时抖动抑制重复通知，严重度升级立即放行，全部留痕。"""

import unittest

from app import ManualClock, Orchestrator


def make_orchestrator(start=1_000.0):
    clock = ManualClock(start)
    return Orchestrator.from_config_dir(clock=clock), clock


class SuppressionTest(unittest.TestCase):
    def test_hundreds_of_duplicate_alarms_produce_one_notification(self):
        orch, clock = make_orchestrator()
        orch.ingest("DRV_OVERCURRENT")
        for _ in range(300):
            clock.advance(0.18)  # 一分钟内约 300 条
            orch.ingest("RBT_STALL")
        inc_id = orch.list_incidents()[0]["id"]
        history = orch.notification_history(inc_id)
        sent = [n for n in history if n.status == "sent"]
        suppressed = [n for n in history if n.status == "suppressed"]
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0].kind, "opened")
        self.assertEqual(len(suppressed), 300)
        self.assertTrue(all(n.reason == "duplicate_within_window" for n in suppressed))

    def test_severity_escalation_bypasses_suppression_window(self):
        orch, clock = make_orchestrator()
        orch.ingest("VIS_LAMP_DIM")  # warning，打开事件
        clock.advance(2)
        orch.ingest("VIS_LAMP_DIM")  # 窗口内重复 → 抑制
        clock.advance(2)
        orch.ingest("VIS_LAMP_FAIL")  # critical 升级 → 必须立即通知
        inc_id = orch.list_incidents()[0]["id"]
        history = orch.notification_history(inc_id)
        sent_kinds = [n.kind for n in history if n.status == "sent"]
        self.assertIn("opened", sent_kinds)
        self.assertIn("escalated", sent_kinds)
        escalated = next(n for n in history if n.kind == "escalated")
        self.assertEqual(escalated.severity.name.lower(), "critical")

    def test_flapping_fault_does_not_spam_notifications(self):
        orch, clock = make_orchestrator()
        orch.grant_permit("P-1", "UNIT-CONV", granted_by="安全员", valid_from=0, valid_to=10_000)
        for _ in range(5):
            orch.ingest("DRV_OVERCURRENT")
            clock.advance(2)
            orch.ingest("DRV_OVERCURRENT_CLR")
            clock.advance(2)
        incidents = orch.list_incidents()
        self.assertEqual(len(incidents), 1)
        inc_id = incidents[0]["id"]
        history = orch.notification_history(inc_id)
        sent = [n for n in history if n.status == "sent"]
        # 打开一次；抖动期间的 reopened/recovered 都被抑制留痕。
        self.assertLessEqual(len(sent), 2)
        self.assertGreater(len([n for n in history if n.status == "suppressed"]), 0)
        # 事件没有被抖动关掉，信号全保留。
        view = orch.operations_view(inc_id)
        self.assertNotEqual(view["state"], "closed")
        self.assertEqual(view["signal_count"], 10)


if __name__ == "__main__":
    unittest.main()

"""控制权与值守员操作：人工接管后自动回调仅留痕，操作留班组与理由。"""

import unittest

from app import ManualClock, OrchestrationError, Orchestrator


def make_orchestrator(start=1_000.0):
    clock = ManualClock(start)
    return Orchestrator.from_config_dir(clock=clock), clock


class ControlOwnershipTest(unittest.TestCase):
    def test_manual_takeover_blocks_automatic_callbacks(self):
        orch, clock = make_orchestrator()
        orch.grant_permit("P-1", "UNIT-CONV", granted_by="安全员", valid_from=0, valid_to=10_000)
        orch.ingest("DRV_OVERCURRENT")
        inc_id = orch.list_incidents()[0]["id"]
        exe = orch.operations_view(inc_id)["playbook"]["steps"][0]["execution_id"]
        orch.take_control(inc_id, operator="张三", shift="甲班", reason="现场核查驱动器")
        view = orch.operations_view(inc_id)
        self.assertEqual(view["control_owner"], "operator")
        self.assertEqual(view["playbook"]["steps"][0]["state"], "waiting")  # 挂起
        # 自动回调到达：仅留痕，不生效，控制权不被夺回。
        result = orch.step_callback(exe, "isolate", succeeded=True)
        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, "manual_control")
        view = orch.operations_view(inc_id)
        self.assertEqual(view["control_owner"], "operator")
        self.assertEqual(view["playbook"]["steps"][0]["state"], "waiting")
        ignored = [a for a in view["audit"] if a["action"] == "ignored_callback"]
        self.assertEqual(len(ignored), 1)
        self.assertEqual(ignored[0]["reason"], "manual_control")

    def test_delegate_back_to_automation_restarts_with_new_execution(self):
        orch, clock = make_orchestrator()
        orch.grant_permit("P-1", "UNIT-CONV", granted_by="安全员", valid_from=0, valid_to=10_000)
        orch.ingest("DRV_OVERCURRENT")
        inc_id = orch.list_incidents()[0]["id"]
        old_exe = orch.operations_view(inc_id)["playbook"]["steps"][0]["execution_id"]
        orch.take_control(inc_id, operator="张三", shift="甲班", reason="人工确认")
        orch.delegate_control(inc_id, "automation", operator="张三", shift="甲班", reason="确认完毕交还")
        view = orch.operations_view(inc_id)
        self.assertEqual(view["control_owner"], "automation")
        new_exe = view["playbook"]["steps"][0]["execution_id"]
        self.assertNotEqual(old_exe, new_exe)
        # 旧执行实例的回调永远失效。
        result = orch.step_callback(old_exe, "isolate", succeeded=True)
        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, "stale_execution")

    def test_operator_actions_record_shift_and_reason(self):
        orch, clock = make_orchestrator()
        orch.grant_permit("P-1", "UNIT-CONV", granted_by="安全员", valid_from=0, valid_to=10_000)
        orch.ingest("DRV_OVERCURRENT")
        inc_id = orch.list_incidents()[0]["id"]
        orch.acknowledge(inc_id, operator="张三", shift="甲班", reason="已收到告警")
        orch.reassign(inc_id, "维修二组", operator="张三", shift="甲班", reason="需要机修到场")
        orch.pause(inc_id, operator="李四", shift="甲班", reason="等待备件")
        orch.resume(inc_id, operator="李四", shift="甲班", reason="备件到位")
        view = orch.operations_view(inc_id)
        by_action = {a["action"]: a for a in view["audit"]}
        for action in ("acknowledged", "reassigned", "paused", "resumed"):
            self.assertIn(action, by_action)
            self.assertEqual(by_action[action]["shift"], "甲班")
            self.assertTrue(by_action[action]["reason"])
        self.assertEqual(view["state"], "acknowledged")
        self.assertEqual(view["assigned_to"], "维修二组")
        self.assertFalse(view["paused"])

    def test_reason_is_mandatory_for_operator_actions(self):
        orch, _ = make_orchestrator()
        orch.ingest("VIS_LAMP_DIM")
        inc_id = orch.list_incidents()[0]["id"]
        with self.assertRaises(OrchestrationError):
            orch.acknowledge(inc_id, operator="张三", shift="甲班", reason="")
        with self.assertRaises(OrchestrationError):
            orch.close(inc_id, operator="张三", shift="甲班", reason="  ")

    def test_close_requires_cleared_evidence_unless_forced(self):
        orch, _ = make_orchestrator()
        orch.grant_permit("P-1", "UNIT-CONV", granted_by="安全员", valid_from=0, valid_to=10_000)
        orch.ingest("DRV_OVERCURRENT")
        inc_id = orch.list_incidents()[0]["id"]
        with self.assertRaises(OrchestrationError):
            orch.close(inc_id, operator="张三", shift="甲班", reason="先结案")
        orch.close(inc_id, operator="张三", shift="甲班", reason="安全员确认可强制结案", force=True)
        view = orch.operations_view(inc_id)
        self.assertEqual(view["state"], "closed")
        close_entry = next(a for a in view["audit"] if a["action"] == "closed")
        self.assertTrue(close_entry["details"]["force"])
        self.assertEqual(close_entry["details"]["remaining_evidence"], ["DRV-101:DRV_OVERCURRENT"])

    def test_merged_incidents_remain_individually_traceable(self):
        orch, clock = make_orchestrator()
        orch.grant_permit("P-1", "UNIT-CONV", granted_by="安全员", valid_from=0, valid_to=10_000)
        orch.ingest("DRV_OVERCURRENT")
        clock.advance(1)
        orch.ingest("VIS_LAMP_DIM")
        primary, secondary = [i["id"] for i in orch.list_incidents()]
        orch.link_incidents(primary, secondary, operator="张三", shift="甲班", reason="同一巡检路线处理")
        p_view = orch.operations_view(primary)
        s_view = orch.operations_view(secondary)
        self.assertEqual(p_view["linked_children"], [secondary])
        self.assertEqual(s_view["merged_into"], primary)
        # 各自的信号与审计仍分别保留。
        self.assertEqual(s_view["signal_count"], 1)
        self.assertEqual(s_view["signals"][0]["alarm_code"], "VIS_LAMP_DIM")
        self.assertTrue(any(a["action"] == "merged_into_primary" for a in s_view["audit"]))


if __name__ == "__main__":
    unittest.main()

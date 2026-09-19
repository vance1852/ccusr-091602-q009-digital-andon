"""端到端：同一驱动器故障引发三个工位的交错告警风暴，走完整个处置闭环。

场景对应需求：一分钟内数百条安灯消息 → 一个有边界的生产事件；
值守员确认 / 转派 / 接管；许可撤销与迟到回调不能误复位设备；
最终视图给出根因候选、受影响单元、控制权、卡住的步骤与通知历史。
"""

import unittest

from app import ManualClock, Orchestrator


def make_orchestrator(start=1_000.0):
    clock = ManualClock(start)
    return Orchestrator.from_config_dir(clock=clock), clock


class EndToEndTest(unittest.TestCase):
    def test_full_drive_fault_scenario(self):
        orch, clock = make_orchestrator()
        orch.grant_permit("P-1", "UNIT-CONV", granted_by="安全员王五", valid_from=0, valid_to=10_000)

        # 1. 驱动器过流 → 事件建立，剧本启动，isolate 自动下发并秒级完成。
        orch.ingest("DRV_OVERCURRENT")
        inc_id = orch.list_incidents()[0]["id"]
        view = orch.operations_view(inc_id)
        self.assertEqual(view["state"], "mitigating")
        isolate_exe = view["playbook"]["steps"][0]["execution_id"]
        result = orch.step_callback(isolate_exe, "isolate", succeeded=True)
        self.assertTrue(result.accepted)

        # 2. 一分钟内三个工位共 300 条交错症状告警 → 仍是一个事件，通知被抑制。
        for _ in range(100):
            clock.advance(0.5)
            orch.ingest("RBT_STALL")
            orch.ingest("CNV_JAM")
            orch.ingest("VIS_REJECT")
        self.assertEqual(len(orch.list_incidents()), 1)
        view = orch.operations_view(inc_id)
        self.assertEqual(view["signal_count"], 301)
        sent = [n for n in view["notifications"] if n["status"] == "sent"]
        self.assertEqual([n["kind"] for n in sent], ["opened"])
        self.assertEqual(len([n for n in view["notifications"] if n["status"] == "suppressed"]), 300)

        # 3. 根因候选：DRV-101 居首；三个单元全部受影响。
        top = view["root_cause_candidates"][0]
        self.assertEqual(top["device"], "DRV-101")
        self.assertEqual({u["unit"] for u in view["affected_units"]},
                         {"UNIT-CONV", "UNIT-ROBOT", "UNIT-VISION"})

        # 4. 值守员确认并转派（此时剧本在等待人工检查）。
        self.assertEqual(view["playbook"]["steps"][1]["state"], "waiting")
        orch.acknowledge(inc_id, operator="张三", shift="甲班", reason="已收到，前往现场")
        orch.reassign(inc_id, "维修二组", operator="张三", shift="甲班", reason="需要机修配合")

        # 5. 驱动恢复信号先到，但三个工位症状仍在 → 事件不得关闭 / 转观察。
        clock.advance(2)
        orch.ingest("DRV_OVERCURRENT_CLR")
        view = orch.operations_view(inc_id)
        self.assertEqual(view["state"], "acknowledged")
        self.assertEqual(len(view["active_evidence"]), 3)

        # 6. 人工检查完成 → 复位步骤被前置条件挡住（证据未清），出现在卡住列表。
        orch.complete_manual_step(inc_id, "inspect", operator="张三", shift="甲班", reason="机械无卡阻")
        view = orch.operations_view(inc_id)
        stuck = {s["step_id"]: s["reason"] for s in view["stuck_steps"]}
        self.assertEqual(stuck.get("reset"), "precondition_unmet:evidence_clear")

        # 7. 人工接管：之后所有自动回调仅留痕，控制权不被夺回。
        orch.take_control(inc_id, operator="张三", shift="甲班", reason="手动盘车检查")
        late = orch.step_callback(isolate_exe, "isolate", succeeded=True)
        self.assertFalse(late.accepted)
        self.assertEqual(late.reason, "manual_control")
        ghost = orch.step_callback("exe-99999", "reset", succeeded=True)
        self.assertFalse(ghost.accepted)
        self.assertEqual(ghost.reason, "unknown_execution")
        view = orch.operations_view(inc_id)
        self.assertEqual(view["control_owner"], "operator")

        # 8. 安全许可被撤销：复位步骤被许可挡住，绝不能下发。
        orch.revoke_permit("P-1", reason="安全联锁触发")
        orch.delegate_control(inc_id, "automation", operator="张三", shift="甲班", reason="盘车完成交还")
        view = orch.operations_view(inc_id)
        stuck = {s["step_id"]: s["reason"] for s in view["stuck_steps"]}
        self.assertIn("permit_invalid", stuck.get("reset", ""))
        dispatched = [
            a["details"].get("action") for a in view["audit"] if a["action"] == "action_dispatched"
        ]
        self.assertNotIn("drive.reset", dispatched)

        # 9. 症状全部恢复 → 事件转观察；换发新许可后复位才执行并完成。
        clock.advance(30)  # 处置持续了数分钟，已出抑制窗口
        for code in ("RBT_STALL_CLR", "CNV_JAM_CLR", "VIS_REJECT_CLR"):
            clock.advance(1)
            orch.ingest(code)
        view = orch.operations_view(inc_id)
        self.assertEqual(view["state"], "monitoring")
        orch.grant_permit("P-2", "UNIT-CONV", granted_by="安全员王五", valid_from=0, valid_to=20_000)
        view = orch.operations_view(inc_id)
        reset = view["playbook"]["steps"][2]
        self.assertEqual(reset["state"], "running")
        orch.step_callback(reset["execution_id"], "reset", succeeded=True)
        view = orch.operations_view(inc_id)
        self.assertEqual(view["playbook"]["status"], "completed")

        # 10. 值守员结案；最终视图完整。
        orch.close(inc_id, operator="张三", shift="甲班", reason="故障排除，恢复生产")
        view = orch.operations_view(inc_id)
        self.assertEqual(view["state"], "closed")
        self.assertEqual(view["control_owner"], "automation")
        self.assertEqual(view["assigned_to"], "维修二组")
        self.assertEqual(view["stuck_steps"], [])
        self.assertEqual(view["signal_count"], 305)  # 301 故障 + 4 恢复
        sent_kinds = [n["kind"] for n in view["notifications"] if n["status"] == "sent"]
        for kind in ("opened", "permit_revoked", "recovered", "closed"):
            self.assertIn(kind, sent_kinds)
        shifts = {a["shift"] for a in view["audit"] if a["shift"]}
        self.assertEqual(shifts, {"甲班"})
        ignored = [a for a in view["audit"] if a["action"] == "ignored_callback"]
        self.assertEqual(len(ignored), 1)  # 人工接管期间的迟到回调
        self.assertEqual(ignored[0]["reason"], "manual_control")
        # 未知执行实例的回调无法归属事件，留在系统级审计。
        ghost = [a for a in orch.audit_trail() if a.action == "ignored_callback"
                 and a.reason == "unknown_execution"]
        self.assertEqual(len(ghost), 1)


if __name__ == "__main__":
    unittest.main()

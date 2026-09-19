"""剧本安全：许可门控、超时补偿、迟到回调不得造成误复位。"""

import unittest

from app import ManualClock, Orchestrator


def make_orchestrator(start=1_000.0):
    clock = ManualClock(start)
    return Orchestrator.from_config_dir(clock=clock), clock


def dispatched_actions(orch, inc_id):
    return [
        a.details.get("action")
        for a in orch.audit_trail(inc_id)
        if a.action == "action_dispatched"
    ]


class PlaybookSafetyTest(unittest.TestCase):
    def test_automatic_step_blocked_without_permit(self):
        orch, _ = make_orchestrator()
        orch.ingest("DRV_OVERCURRENT")
        inc_id = orch.list_incidents()[0]["id"]
        view = orch.operations_view(inc_id)
        isolate = view["playbook"]["steps"][0]
        self.assertEqual(isolate["state"], "pending")
        self.assertEqual(isolate["blocked_reason"], "permit_invalid")
        self.assertEqual(dispatched_actions(orch, inc_id), [])
        # 签发许可后步骤才启动。
        orch.grant_permit("P-1", "UNIT-CONV", granted_by="安全员", valid_from=0, valid_to=10_000)
        view = orch.operations_view(inc_id)
        self.assertEqual(view["playbook"]["steps"][0]["state"], "running")
        self.assertEqual(dispatched_actions(orch, inc_id), ["drive.isolate"])

    def test_timeout_fails_step_and_runs_compensation(self):
        orch, clock = make_orchestrator()
        orch.grant_permit("P-1", "UNIT-CONV", granted_by="安全员", valid_from=0, valid_to=10_000)
        orch.ingest("DRV_OVERCURRENT")
        inc_id = orch.list_incidents()[0]["id"]
        clock.advance(31)  # isolate 超时（30s）
        orch.tick()
        view = orch.operations_view(inc_id)
        isolate = view["playbook"]["steps"][0]
        self.assertEqual(isolate["state"], "failed")
        self.assertEqual(isolate["failure_reason"], "timeout")
        self.assertEqual(isolate["compensation"]["action"], "drive.safe_state")
        self.assertEqual(view["playbook"]["status"], "halted")
        kinds = [n["kind"] for n in view["notifications"] if n["status"] == "sent"]
        self.assertIn("step_failed", kinds)

    def test_late_callback_after_timeout_is_ignored(self):
        orch, clock = make_orchestrator()
        orch.grant_permit("P-1", "UNIT-CONV", granted_by="安全员", valid_from=0, valid_to=10_000)
        orch.ingest("DRV_OVERCURRENT")
        inc_id = orch.list_incidents()[0]["id"]
        exe = orch.operations_view(inc_id)["playbook"]["steps"][0]["execution_id"]
        clock.advance(31)
        orch.tick()  # 超时失败并补偿
        result = orch.step_callback(exe, "isolate", succeeded=True)  # 迟到的成功回调
        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, "stale_execution")
        view = orch.operations_view(inc_id)
        isolate = view["playbook"]["steps"][0]
        self.assertEqual(isolate["state"], "failed")  # 状态没有被迟到回调改写
        ignored = [a for a in view["audit"] if a["action"] == "ignored_callback"]
        self.assertEqual(len(ignored), 1)

    def test_permit_revocation_aborts_running_step_and_blocks_reset(self):
        orch, clock = make_orchestrator()
        orch.grant_permit("P-1", "UNIT-CONV", granted_by="安全员", valid_from=0, valid_to=10_000)
        orch.ingest("DRV_OVERCURRENT")
        inc_id = orch.list_incidents()[0]["id"]
        exe = orch.operations_view(inc_id)["playbook"]["steps"][0]["execution_id"]
        clock.advance(5)
        orch.revoke_permit("P-1", reason="安全联锁触发")
        view = orch.operations_view(inc_id)
        isolate = view["playbook"]["steps"][0]
        self.assertEqual(isolate["state"], "failed")
        self.assertEqual(isolate["failure_reason"], "permit_revoked")
        self.assertEqual(isolate["compensation"]["action"], "drive.safe_state")
        # 许可撤销后，复位步骤绝不能下发。
        self.assertNotIn("drive.reset", dispatched_actions(orch, inc_id))
        # 迟到的回调同样无效。
        result = orch.step_callback(exe, "isolate", succeeded=True)
        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, "stale_execution")
        self.assertNotIn("drive.reset", dispatched_actions(orch, inc_id))
        kinds = [n["kind"] for n in view["notifications"] if n["status"] == "sent"]
        self.assertIn("permit_revoked", kinds)

    def test_reset_waits_for_evidence_clear_precondition(self):
        orch, clock = make_orchestrator()
        orch.grant_permit("P-1", "UNIT-CONV", granted_by="安全员", valid_from=0, valid_to=10_000)
        orch.ingest("DRV_OVERCURRENT")
        inc_id = orch.list_incidents()[0]["id"]
        exe = orch.operations_view(inc_id)["playbook"]["steps"][0]["execution_id"]
        orch.step_callback(exe, "isolate", succeeded=True)
        orch.complete_manual_step(inc_id, "inspect", operator="张三", shift="甲班", reason="现场无异常")
        view = orch.operations_view(inc_id)
        reset = view["playbook"]["steps"][2]
        self.assertEqual(reset["state"], "pending")
        self.assertEqual(reset["blocked_reason"], "precondition_unmet:evidence_clear")
        self.assertNotIn("drive.reset", dispatched_actions(orch, inc_id))
        # 证据清除后前置条件满足，复位才允许下发。
        orch.ingest("DRV_OVERCURRENT_CLR")
        view = orch.operations_view(inc_id)
        self.assertEqual(view["playbook"]["steps"][2]["state"], "running")
        self.assertIn("drive.reset", dispatched_actions(orch, inc_id))

    def test_compensation_requiring_permit_defers_when_permit_invalid(self):
        # 临时剧本：补偿也需要许可 → 许可无效时步骤停在 compensating（卡住可见）。
        orch, clock = make_orchestrator()
        defs = dict(orch.playbook_defs)
        drive = defs["drive_fault"]
        steps = list(drive.steps)
        isolate = steps[0]
        steps[0] = type(isolate)(
            step_id=isolate.step_id, name=isolate.name, kind=isolate.kind,
            action=isolate.action, requires_permit=False, timeout_seconds=10,
            preconditions=(), compensation={"action": "drive.lockout", "requires_permit": True},
        )
        defs["drive_fault"] = type(drive)(
            playbook_id=drive.playbook_id, incident_type=drive.incident_type,
            permit_scope="UNIT-CONV", steps=tuple(steps),
        )
        orch.playbook_defs = defs
        orch.ingest("DRV_OVERCURRENT")
        inc_id = orch.list_incidents()[0]["id"]
        clock.advance(11)
        orch.tick()
        view = orch.operations_view(inc_id)
        isolate_view = view["playbook"]["steps"][0]
        self.assertEqual(isolate_view["state"], "compensating")
        stuck = {s["step_id"]: s["reason"] for s in view["stuck_steps"]}
        self.assertEqual(stuck.get("isolate"), "compensation_deferred")
        # 补发许可后补偿执行、步骤落定。
        orch.grant_permit("P-9", "UNIT-CONV", granted_by="安全员", valid_from=0, valid_to=10_000)
        view = orch.operations_view(inc_id)
        self.assertEqual(view["playbook"]["steps"][0]["state"], "failed")


if __name__ == "__main__":
    unittest.main()

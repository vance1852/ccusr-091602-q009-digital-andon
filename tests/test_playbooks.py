"""处置剧本、安全许可、超时补偿、人工接管影子回调测试。"""
import unittest

from app.bootstrap import build_engine
from app.engine import CallbackVerdict
from app.model import (
    STEP_COMPENSATING,
    STEP_COMPLETED,
    STEP_FAILED,
    STEP_PENDING,
    STEP_RUNNING,
    STEP_WAITING,
)
from app.safety import ACTION_RESET


def _sig(ts, device, code, payload=None, severity=None):
    out = {"ts": ts, "device": device, "code": code,
           "payload": payload or {}}
    if severity:
        out["severity"] = severity
    return out


class PlaybookSafetyTest(unittest.TestCase):
    def setUp(self):
        self.engine = build_engine()

    def _open_drive_incident(self, ts=1000):
        e = self.engine
        e.ingest(_sig(ts, "SERVO-A1", "E1001", {"axis": "X1"}))
        return e.incidents["INC-0001"], e.runs["INC-0001"]

    def test_no_permit_blocks_auto_step_and_records_it(self):
        e = self.engine
        inc, run = self._open_drive_incident()
        # 默认没有任何许可：s1 停在 waiting，无指令发出
        self.assertEqual(run.run_of("s1_safe_torque_off").state, STEP_WAITING)
        self.assertIn("安全裁决拒绝",
                      run.run_of("s1_safe_torque_off").wait_reason)
        self.assertEqual(e.gateway.log, [])
        blocked = [a for a in e.audits if a.action == "auto-step-blocked"]
        self.assertTrue(blocked)

    def test_interlock_overrides_permit(self):
        e = self.engine
        inc, run = self._open_drive_incident()
        # 先有活动联锁，再签发许可：许可也不能越过联锁
        e.safety.interlock("device", "SERVO-A1", 1050, "围栏门打开")
        e.grant_permit("unit", "cell-A", "power", 1100, reason="复产授权")
        e.tick(1200)
        self.assertEqual(run.run_of("s1_safe_torque_off").state, STEP_WAITING)
        self.assertIn("联锁",
                      run.run_of("s1_safe_torque_off").wait_reason)
        self.assertEqual(e.gateway.log, [])
        # 联锁清除后同一许可生效，步骤下发
        e.safety.clear_interlock("device", "SERVO-A1", "围栏门关闭", 1300)
        e.tick(1400)
        self.assertEqual(run.run_of("s1_safe_torque_off").state, STEP_RUNNING)

    def test_permit_granted_dispatches_and_callback_advances(self):
        e = self.engine
        inc, run = self._open_drive_incident()
        e.grant_permit("unit", "cell-A", "power", 1000, reason="复产授权")
        s1 = run.run_of("s1_safe_torque_off")
        self.assertEqual(s1.state, STEP_RUNNING)
        dispatch_id = s1.dispatch_id
        pending = {p.dispatch_id for p in e.gateway.pending()}
        self.assertIn(dispatch_id, pending)

        # 回调必须携带实例与步骤标识；错误身份被丢弃
        verdict, _ = e.handle_callback(
            dispatch_id=dispatch_id, instance_id="RUN-WRONG",
            step_id="s1_safe_torque_off", success=True, ts=2000)
        self.assertEqual(verdict, CallbackVerdict.IGNORED)
        self.assertEqual(s1.state, STEP_RUNNING)

        # 正确回调推进到人工步骤
        verdict, _ = e.handle_callback(
            dispatch_id=dispatch_id, instance_id="RUN-INC-0001",
            step_id="s1_safe_torque_off", success=True, ts=2000)
        self.assertEqual(verdict, CallbackVerdict.APPLIED)
        self.assertEqual(s1.state, STEP_COMPLETED)
        s2 = run.run_of("s2_field_inspect")
        self.assertEqual(s2.state, STEP_WAITING)

    def test_timeout_triggers_compensation_then_safe_hold(self):
        e = self.engine
        inc, run = self._open_drive_incident()
        e.grant_permit("unit", "cell-A", "power", 1000, reason="复产授权")
        s1 = run.run_of("s1_safe_torque_off")
        dispatch_id = s1.dispatch_id
        # 不回调，推进到 4000ms 超时点之后
        e.tick(5100)
        # 超时 -> 补偿(同 power 许可) 已下发，停在 compensating 等回调
        self.assertEqual(s1.state, STEP_COMPENSATING)
        comp_cmds = [r for r in e.gateway.log if r.action ==
                     "engage_dynamic_brake"]
        self.assertEqual(len(comp_cmds), 1)
        comp_dispatch = comp_cmds[0].dispatch_id
        # 补偿成功回调：步骤判失败，等人，不再自动前进
        verdict, _ = e.handle_callback(
            dispatch_id=comp_dispatch, instance_id="RUN-INC-0001",
            step_id="s1_safe_torque_off", success=True, ts=5200,
            detail="动力制动已投入")
        self.assertEqual(verdict, CallbackVerdict.APPLIED)
        self.assertEqual(s1.state, STEP_FAILED)
        self.assertEqual(run.status, "failed")

    def test_permit_revocation_holds_compensation_in_safe_state(self):
        e = self.engine
        inc, run = self._open_drive_incident()
        e.grant_permit("unit", "cell-A", "power", 1000, reason="复产授权")
        s1 = run.run_of("s1_safe_torque_off")
        e.tick(5100)  # 触发补偿且补偿已随 power 许可下发
        # 撤销 power：控制权收归 safety，补偿回调到达只能影子留痕
        e.revoke_permit("unit", "cell-A", "power", 5300,
                        reason="安全员进入围栏")
        self.assertEqual(inc.control_owner, "safety")
        comp_dispatch = [r for r in e.gateway.log
                         if r.action == "engage_dynamic_brake"][0].dispatch_id
        verdict, _ = e.handle_callback(
            dispatch_id=comp_dispatch, instance_id="RUN-INC-0001",
            step_id="s1_safe_torque_off", success=True, ts=5400)
        self.assertEqual(verdict, CallbackVerdict.SHADOW)
        self.assertEqual(s1.state, STEP_COMPENSATING)
        # 设备指令层面没有任何新的复位/复产指令
        self.assertFalse(
            any(r.action in ("reset_drive", "restart_line")
                for r in e.gateway.log))

    def test_in_flight_callback_after_human_takeover_is_shadow(self):
        e = self.engine
        inc, run = self._open_drive_incident()
        e.grant_permit("unit", "cell-A", "power", 1000, reason="复产授权")
        s1 = run.run_of("s1_safe_torque_off")
        dispatch_id = s1.dispatch_id
        # 值守员在回调到达前接管
        e.take_control("INC-0001", actor="李值守", team="shift-A",
                       reason="现场判断需人工处理", ts=3000)
        self.assertEqual(inc.control_owner, "operator")
        verdict, _ = e.handle_callback(
            dispatch_id=dispatch_id, instance_id="RUN-INC-0001",
            step_id="s1_safe_torque_off", success=True, ts=4000,
            detail="驱动器报告STO完成")
        self.assertEqual(verdict, CallbackVerdict.SHADOW)
        # 步骤保持 running，未被回调推进
        self.assertEqual(s1.state, STEP_RUNNING)
        # 接管后自动侧 pump 也不会再下发任何新指令
        before = len(e.gateway.log)
        e.tick(4500)
        self.assertEqual(len(e.gateway.log), before)

    def test_late_callback_after_close_is_shadow_and_no_reset(self):
        e = self.engine
        inc, run = self._open_drive_incident()
        e.grant_permit("unit", "cell-A", "power", 1000, reason="复产授权")
        dispatch_id = run.run_of("s1_safe_torque_off").dispatch_id
        e.take_control("INC-0001", actor="李值守", team="shift-A",
                       reason="人工结案处理", ts=2000)
        e.close_incident("INC-0001", actor="李值守", team="shift-A",
                         reason="检修完成按规结案", ts=2100)
        # 结案后迟到的"成功"回调不得复位/推进任何东西
        verdict, _ = e.handle_callback(
            dispatch_id=dispatch_id, instance_id="RUN-INC-0001",
            step_id="s1_safe_torque_off", success=True, ts=9000)
        self.assertEqual(verdict, CallbackVerdict.SHADOW)
        self.assertFalse(
            any(r.action in ("reset_drive", "restart_line")
                for r in e.gateway.log))

    def test_duplicate_callback_ignored(self):
        e = self.engine
        inc, run = self._open_drive_incident()
        e.grant_permit("unit", "cell-A", "power", 1000, reason="复产授权")
        dispatch_id = run.run_of("s1_safe_torque_off").dispatch_id
        v1, _ = e.handle_callback(
            dispatch_id=dispatch_id, instance_id="RUN-INC-0001",
            step_id="s1_safe_torque_off", success=True, ts=2000)
        v2, _ = e.handle_callback(
            dispatch_id=dispatch_id, instance_id="RUN-INC-0001",
            step_id="s1_safe_torque_off", success=True, ts=2100)
        self.assertEqual(v1, CallbackVerdict.APPLIED)
        self.assertEqual(v2, CallbackVerdict.IGNORED)

    def test_reset_step_requires_cleared_evidence_and_ack(self):
        e = self.engine
        inc, run = self._open_drive_incident()
        e.grant_permit("unit", "cell-A", "power", 1000, reason="STO授权")
        # s1 完成、s2 人工完成
        e.handle_callback(
            dispatch_id=run.run_of("s1_safe_torque_off").dispatch_id,
            instance_id="RUN-INC-0001", step_id="s1_safe_torque_off",
            success=True, ts=2000)
        e.complete_manual_step(
            "INC-0001", "s2_field_inspect", actor="王钳工",
            team="maintenance", note="机械链路无卡滞", ts=2500)
        s3 = run.run_of("s3_reset_drive")
        # 即便有 reset 许可，故障证据还在 -> 阻断
        e.grant_permit("unit", "cell-A", "reset", 2600, reason="复位授权")
        e.tick(2700)
        self.assertEqual(s3.state, STEP_WAITING)
        self.assertIn("活动证据", s3.wait_reason)
        # 证据恢复但未确认 -> 仍阻断
        e.ingest(_sig(2800, "SERVO-A1", "C1001", {"axis": "X1"}))
        e.tick(2900)
        self.assertEqual(s3.state, STEP_WAITING)
        self.assertIn("确认", s3.wait_reason)
        # 确认后才下发复位
        e.acknowledge("INC-0001", actor="李值守", team="shift-A",
                      reason="现场就绪，确认复位", ts=3000)
        self.assertEqual(s3.state, STEP_RUNNING)
        self.assertEqual(
            [r for r in e.gateway.log if r.action == "reset_drive"][0]
            .device_id,
            "SERVO-A1",
        )

    def test_recurring_fault_does_not_auto_rerun_completed_playbook(self):
        e = self.engine
        inc, run = self._open_drive_incident()
        e.grant_permit("unit", "cell-A", "power", 1000, reason="STO授权")
        # 走完整条自动复产链路
        e.handle_callback(
            dispatch_id=run.run_of("s1_safe_torque_off").dispatch_id,
            instance_id="RUN-INC-0001", step_id="s1_safe_torque_off",
            success=True, ts=2000)
        e.complete_manual_step(
            "INC-0001", "s2_field_inspect", actor="王钳工",
            team="maintenance", note="检查无异常", ts=2500)
        e.ingest(_sig(2600, "SERVO-A1", "C1001", {"axis": "X1"}))
        e.acknowledge("INC-0001", actor="李值守", team="shift-A",
                      reason="现场就绪", ts=2700)
        e.grant_permit("unit", "cell-A", "reset", 2800, reason="复位授权")
        e.handle_callback(
            dispatch_id=run.run_of("s3_reset_drive").dispatch_id,
            instance_id="RUN-INC-0001", step_id="s3_reset_drive",
            success=True, ts=3000)
        e.grant_permit("unit", "cell-A", "start", 3100, reason="复产授权")
        e.handle_callback(
            dispatch_id=run.run_of("s4_restart_line").dispatch_id,
            instance_id="RUN-INC-0001", step_id="s4_restart_line",
            success=True, ts=3200)
        self.assertTrue(run.is_done())
        self.assertEqual(inc.state, "monitoring")
        # 观察期内故障反复（许可仍然全部有效）
        cmds_before = len(e.gateway.log)
        e.ingest(_sig(4000, "SERVO-A1", "E1001", {"axis": "X1"}))
        self.assertEqual(inc.state, "mitigating")
        # 已完成的剧本不自动重跑：没有任何新指令下发
        self.assertEqual(len(e.gateway.log), cmds_before)
        self.assertTrue(run.is_done())


class EstopManualOnlyTest(unittest.TestCase):
    def test_estop_playbook_never_auto_arms(self):
        e = build_engine()
        e.ingest(_sig(1000, "ESTOP-A1", "E9000"))
        inc = e.incidents["INC-0001"]
        run = e.runs["INC-0001"]
        self.assertEqual(run.status, "armed")
        self.assertEqual(inc.state, "open")
        # 无论授什么许可都不会有自动指令
        e.grant_permit("global", "*", "reset", 1200, reason="错误授权")
        e.tick(5000)
        self.assertEqual(e.gateway.log, [])
        # 人工逐步完成
        e.acknowledge("INC-0001", actor="安全员", team="safety",
                      reason="急停响应", ts=6000)
        e.take_control("INC-0001", actor="安全员", team="safety",
                       reason="急停必须人工处置", ts=6100, owner="safety")
        e.complete_manual_step("INC-0001", "e1_verify_loop",
                               actor="安全员", team="safety",
                               note="回路无短接，现场无人", ts=6200)
        e.complete_manual_step("INC-0001", "e2_release_estop",
                               actor="安全员", team="safety",
                               note="按规程释放", ts=6300)
        e.complete_manual_step("INC-0001", "e3_manual_reset",
                               actor="安全员", team="safety",
                               note="人工复位使能完成", ts=6400)
        self.assertTrue(run.is_done())


class HumanActionAuditTest(unittest.TestCase):
    def test_ack_transfer_pause_close_keep_team_and_reason(self):
        e = build_engine()
        e.ingest(_sig(1000, "SERVO-A1", "E1001", {"axis": "X1"}))
        e.acknowledge("INC-0001", actor="李值守", team="shift-A",
                      reason="已到场", ts=2000)
        e.transfer("INC-0001", "maintenance", actor="李值守",
                   team="shift-A", reason="需要机械维修", ts=3000)
        inc = e.incidents["INC-0001"]
        self.assertEqual(inc.control.team, "maintenance")
        self.assertEqual(inc.control.owner, "operator")
        e.pause_playbook("INC-0001", actor="维修班长", team="maintenance",
                         reason="等备件", ts=4000)
        self.assertTrue(e.runs["INC-0001"].paused)
        e.resume_playbook("INC-0001", actor="维修班长", team="maintenance",
                          reason="备件到位", ts=5000)
        e.take_control("INC-0001", actor="维修班长", team="maintenance",
                       reason="保持人工", ts=5100)
        e.close_incident("INC-0001", actor="维修班长", team="maintenance",
                         reason="维修完成", ts=9000)
        actions = {a.action for a in e.audits}
        for required in ("incident-acknowledged", "incident-transferred",
                         "playbook-paused", "playbook-resumed",
                         "incident-closed"):
            self.assertIn(required, actions)
        closed = [a for a in e.audits if a.action == "incident-closed"][0]
        self.assertEqual(closed.team, "maintenance")
        self.assertEqual(closed.reason, "维修完成")


if __name__ == "__main__":
    unittest.main()

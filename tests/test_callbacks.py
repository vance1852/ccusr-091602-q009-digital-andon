"""回调身份/迟到与拓扑版本的附加安全回归测试。"""
import json
import unittest
from pathlib import Path

from app.bootstrap import build_engine
from app.engine import CallbackVerdict

DATA = Path(__file__).resolve().parent.parent / "data"


def _sig(ts, device, code, payload=None):
    return {"ts": ts, "device": device, "code": code, "payload": payload or {}}


class CallbackAndVersioningTest(unittest.TestCase):
    def test_stale_action_callback_after_timeout_is_ignored(self):
        e = build_engine()
        e.ingest(_sig(1000, "SERVO-A1", "E1001", {"axis": "X1"}))
        e.grant_permit("unit", "cell-A", "power", 1000, reason="授权")
        run = e.runs["INC-0001"]
        stale_dispatch = run.run_of("s1_safe_torque_off").dispatch_id
        e.tick(5100)  # 超时 -> 补偿启动，原挂起身份注销
        # 原动作的"成功"回调迟到：必须忽略，不能把步骤误标完成
        verdict, _ = e.handle_callback(
            dispatch_id=stale_dispatch, instance_id="RUN-INC-0001",
            step_id="s1_safe_torque_off", success=True, ts=5200)
        self.assertEqual(verdict, CallbackVerdict.IGNORED)
        self.assertEqual(run.run_of("s1_safe_torque_off").state,
                         "compensating")

    def test_repeated_ticks_are_idempotent(self):
        e = build_engine()
        e.ingest(_sig(1000, "SERVO-A1", "E1001", {"axis": "X1"}))
        audits0 = len(e.audits)
        notes0 = len(e.notifications.history())
        for t in range(1100, 9000, 100):
            e.tick(t)
        self.assertEqual(len(e.audits), audits0)
        self.assertEqual(len(e.notifications.history()), notes0)

    def test_historical_signals_use_topology_version_at_timestamp(self):
        e = build_engine()
        # 旧版本拓扑（<1000000000000）中没有 VIS-A2，新设备告警无法映射到单元，
        # 但不应抛错；版本选择逻辑取 v1
        old = e.topo.version_at(999_000_000_000)
        new = e.topo.version_at(1_000_000_000_000)
        self.assertEqual(old.version, "topo-2026-01")
        self.assertNotIn("VIS-A2", old.devices)
        self.assertIn("VIS-A2", new.devices)

    def test_scenario_file_replays_deterministically(self):
        e1, e2 = build_engine(), build_engine()
        sigs = json.loads((DATA / "scenario_signals.json").read_text("utf-8"))
        e1.ingest_many(sigs)
        e2.ingest_many(sigs)
        r1 = e1.situation_report("INC-0001")
        r2 = e2.situation_report("INC-0001")
        self.assertEqual(
            [(e["device"], e["code"], e["active"], e["raised_count"])
             for e in r1["evidence"]],
            [(e["device"], e["code"], e["active"], e["raised_count"])
             for e in r2["evidence"]],
        )
        self.assertEqual(
            [n["decision"] for n in r1["notifications"]],
            [n["decision"] for n in r2["notifications"]],
        )

    def test_permit_specificity_device_over_unit(self):
        e = build_engine()
        e.ingest(_sig(1000, "SERVO-A1", "E1001", {"axis": "X1"}))
        # 单元级拒绝不存在时不给许可；设备级许可也应放行同单元动作
        e.grant_permit("device", "SERVO-A1", "power", 1000, reason="单点授权")
        run = e.runs["INC-0001"]
        self.assertEqual(run.run_of("s1_safe_torque_off").state, "running")


if __name__ == "__main__":
    unittest.main()

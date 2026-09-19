"""证据生命周期：恢复信号精确熄灭、晚到清除不得关闭仍被支撑的事件。"""
import unittest

from app.bootstrap import build_engine
from app.model import Severity


def _signal(ts, device, code, kind=None, payload=None, severity=None):
    s = {"ts": ts, "device": device, "code": code}
    if kind:
        s["kind"] = kind
    if payload is not None:
        s["payload"] = payload
    if severity:
        s["severity"] = severity
    return s


class EvidenceLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.engine = build_engine(auto_close_grace_ms=30_000)

    def test_partial_recovery_keeps_incident_open(self):
        e = self.engine
        e.ingest(_signal(1000, "SERVO-A1", "E1001", payload={"axis": "X1"}))
        e.ingest(_signal(1100, "CONV-A1", "E3002"))
        # 事件经传播合并为一个
        inc = e.open_incidents()[0]
        self.assertEqual(len(inc.active_evidence), 2)

        # 只恢复输送线：驱动器仍在报，事件不得结案
        e.ingest(_signal(2000, "CONV-A1", "C3002"))
        inc = e.open_incidents()[0]
        self.assertEqual(inc.state, "mitigating")
        self.assertEqual(inc.close_blockers(), ("SERVO-A1:E1001",))
        self.assertEqual(len(inc.active_evidence), 1)

    def test_late_clear_does_not_close_or_reopen_anything(self):
        e = self.engine
        e.ingest(_signal(1000, "SERVO-A1", "E1001", payload={"axis": "X1"}))
        # 人工直接结案（证据仍在，强制结案留痕）
        e.close_incident("INC-0001", actor="张工", team="maintenance",
                         reason="现场确认停机检修", ts=5000)
        # 之后恢复信号才晚到
        result = e.ingest(_signal(8000, "SERVO-A1", "C1001",
                                  payload={"axis": "X1"}))
        inc = e.incidents["INC-0001"]
        self.assertEqual(inc.state, "closed")
        # 晚到信号挂靠到历史事件仅为追溯，证据状态不被改写
        self.assertTrue(all(ev.active for ev in inc.evidence.values()))
        self.assertIsNotNone(result)
        self.assertEqual(result.id, "INC-0001")
        stale = [a for a in e.audits if a.action == "clear-ignored-stale"]
        self.assertTrue(stale)

    def test_clear_for_wrong_axis_does_not_clear(self):
        e = self.engine
        e.ingest(_signal(1000, "SERVO-A1", "E1001", payload={"axis": "X1"}))
        # X2 轴的恢复不能熄灭 X1 的证据
        e.ingest(_signal(2000, "SERVO-A1", "C1001", payload={"axis": "X2"}))
        inc = e.open_incidents()[0]
        self.assertEqual(len(inc.active_evidence), 1)
        self.assertEqual(inc.active_evidence[0].correlation,
                         frozenset({("axis", "X1")}))

    def test_recurrence_after_full_clear_reactivates(self):
        e = self.engine
        for ts, code in [(1000, "E1001"), (1100, "E1001"), (1200, "E1001")]:
            e.ingest(_signal(ts, "SERVO-A1", code, payload={"axis": "X1"}))
        inc = e.open_incidents()[0]
        e.ingest(_signal(3000, "SERVO-A1", "C1001", payload={"axis": "X1"}))
        # 剧本未走完，不会自动结案
        inc = e.incidents["INC-0001"]
        self.assertFalse(inc.active_evidence)
        # 故障反复：重新激活同一证据
        e.ingest(_signal(6000, "SERVO-A1", "E1001", payload={"axis": "X1"}))
        inc = e.open_incidents()[0]
        ev = [x for x in inc.evidence.values() if x.code == "E1001"][0]
        self.assertTrue(ev.active)
        self.assertEqual(ev.raised_count, 4)
        self.assertEqual(inc.state, "mitigating")


if __name__ == "__main__":
    unittest.main()

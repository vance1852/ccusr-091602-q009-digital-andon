"""告警归并、抖动抑制、严重度升级、信号台账测试。"""
import json
import unittest
from pathlib import Path

from app.bootstrap import build_engine
from app.notifications import NOTIFY_ESCALATION, NOTIFY_SENT, NOTIFY_SUPPRESSED

DATA = Path(__file__).resolve().parent.parent / "data"


def _storm(engine, upto=None):
    sigs = json.loads((DATA / "scenario_signals.json").read_text("utf-8"))
    if upto is not None:
        sigs = [s for s in sigs if s["ts"] <= upto]
    engine.ingest_many(sigs)
    return sigs


class CorrelationTest(unittest.TestCase):
    def setUp(self):
        self.engine = build_engine()

    def test_storm_merges_into_one_bounded_incident(self):
        _storm(self.engine, upto=60_600)
        open_incs = self.engine.open_incidents()
        self.assertEqual(len(open_incs), 1)
        inc = open_incs[0]
        self.assertEqual(inc.type, "motion_line_down")
        self.assertEqual(
            sorted(inc.devices),
            ["CONV-A1", "ROBOT-A1", "SERVO-A1", "VIS-A1"],
        )

    def test_downstream_first_then_root_cause_gets_merged(self):
        e = self.engine
        # 机器人先因 STO 停机（非根因证据），随后根因驱动器才报出
        e.ingest({"ts": 1000, "device": "ROBOT-A1", "code": "E4105"})
        self.assertEqual(len(e.open_incidents()), 1)
        e.ingest({"ts": 1100, "device": "SERVO-A1", "code": "E1001",
                  "payload": {"axis": "X1"}})
        # 传播关系把两个事件关联合并（先打开的机器人事件为存活方）
        self.assertEqual(len(e.open_incidents()), 1)
        survivor = e.open_incidents()[0]
        self.assertEqual(survivor.id, "INC-0001")
        self.assertEqual(survivor.merged_children, ["INC-0002"])
        self.assertEqual(e.incidents["INC-0002"].merged_into, "INC-0001")
        # 被合并事件的信号仍可分别追溯：原始事件与最终事件都有记录
        recs = e.ledger.by_incident("INC-0002")
        self.assertTrue(any(r.original_incident_id == "INC-0002"
                            and r.final_incident_id == "INC-0001"
                            and "INC-0002" in r.merged_via
                            for r in recs))

    def test_raw_signals_never_dropped(self):
        sigs = _storm(self.engine)
        # 17 条交错信号一条不少
        self.assertEqual(self.engine.ledger.count(), len(sigs))
        recs = self.engine.ledger.all()
        for r in recs:
            self.assertIsNotNone(r.final_incident_id)
            self.assertIn(r.signal.kind, ("raise", "clear"))

    def test_jitter_duplicates_suppressed_within_window(self):
        _storm(self.engine, upto=60_220)
        inc = self.engine.open_incidents()[0]
        suppressed = [n for n in self.engine.notifications.history(inc.id)
                      if n.decision == NOTIFY_SUPPRESSED]
        # 60150/60180/60220 三次重复 E1001 均落在 2000ms 抖动窗口内
        self.assertGreaterEqual(len(suppressed), 2)
        # 证据只算一条，出现次数累加
        ev = [e for e in inc.evidence.values()
              if e.device_id == "SERVO-A1" and e.code == "E1001"][0]
        self.assertEqual(ev.raised_count, 4)

    def test_severity_escalation_pierces_suppression_immediately(self):
        _storm(self.engine, upto=60_600)
        inc = self.engine.open_incidents()[0]
        self.assertEqual(inc.severity.name, "CRITICAL")
        crit = [n for n in self.engine.notifications.history(inc.id)
                if n.level == "CRITICAL"]
        self.assertTrue(crit, "严重度升级必须立即产生 CRITICAL 通知")
        self.assertIn(crit[0].decision, (NOTIFY_SENT, NOTIFY_ESCALATION))
        self.assertIn("升级", crit[0].title)

    def test_duplicate_after_escalation_back_in_window(self):
        # 60500 CRITICAL 升级后，60600 同指纹 HIGH 重复仍应被抑制（不可再发一条）
        _storm(self.engine, upto=60_600)
        inc = self.engine.open_incidents()[0]
        last_note = self.engine.notifications.history(inc.id)[-1]
        self.assertEqual(last_note.decision, NOTIFY_SUPPRESSED)

    def test_spread_notification_only_for_new_device(self):
        _storm(self.engine, upto=60_420)
        inc = self.engine.open_incidents()[0]
        spreads = [n for n in self.engine.notifications.history(inc.id)
                   if "扩散" in n.title]
        spread_devices = {n.title.split("] ", 1)[1].split(":", 1)[0]
                          for n in spreads}
        # 机器人/输送线/视觉各一条，伺服自身重复不算扩散
        self.assertEqual(spread_devices,
                         {"ROBOT-A1", "CONV-A1", "VIS-A1"})


if __name__ == "__main__":
    unittest.main()

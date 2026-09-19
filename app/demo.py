"""端到端演示：从一分钟数百条告警到一份可处置的态势。

运行：

    python -m app.demo

两段剧情：
A. 直接回放 data/scenario_signals.json 的交错告警，展示归并边界、
   抖动抑制、严重度升级、信号全留存；
B. 剧本化处置全链路：许可生效才自动动作；许可撤销后迟到回调只留痕；
   故障反复不自动重跑剧本；结案后的晚到恢复信号不改变任何状态。
"""
from __future__ import annotations

import json
from pathlib import Path

from .bootstrap import build_engine
from .engine import CallbackVerdict
from .notifications import (
    NOTIFY_ESCALATION,
    NOTIFY_SENT,
    NOTIFY_SUPPRESSED,
)

DATA = Path(__file__).resolve().parent.parent / "data"


def hr(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def show_report(engine, inc_id: str) -> None:
    rep = engine.situation_report(inc_id)
    inc = rep["incident"]
    print(f"事件 {inc['id']}  类型={inc['type']}  状态={inc['state']}  "
          f"级别={inc['severity']}")
    print(f"受影响单元: {rep['impacted_units']}")
    print(f"受影响设备: {inc['devices']}")
    print("根因候选:")
    for c in rep["root_cause_candidates"]:
        print(f"  - {c['device']:<9} score={c['score']:<3} "
              f"{c['rationale']}  证据码={c['supporting_codes']}")
    ctrl = rep["control"]
    print(f"控制权: {ctrl['owner']}（{ctrl['team']}/{ctrl['actor']}，"
          f"自 ts={ctrl['since_ts']}，交接 {ctrl['handover_count']} 次）")
    print(f"活动证据/结案阻断: {inc['close_blockers'] or '无'}")
    if rep["playbook"]:
        pb = rep["playbook"]
        print(f"剧本 {pb['playbook_id']} 状态={pb['status']}  "
              f"当前步骤={pb['current_step']}")
        for s in pb["steps"]:
            mark = {"completed": "✓", "running": "►", "waiting": "…",
                    "compensating": "⚠", "failed": "✗",
                    "pending": "·"}.get(s["state"], "?")
            note = f"  {s['note']}" if s["note"] else ""
            print(f"   {mark} {s['step_id']:<22}{s['state']}{note}")
    if rep["stuck_steps"]:
        print("卡住的步骤:")
        for st in rep["stuck_steps"]:
            print(f"  ! {st['step_id']} [{st['state']}] {st['reason']}")


def show_notifications(engine, inc_id: str) -> None:
    history = engine.notifications.history(inc_id)
    sent = [n for n in history if n.decision in (NOTIFY_SENT, NOTIFY_ESCALATION)]
    suppressed = [n for n in history if n.decision == NOTIFY_SUPPRESSED]
    print(f"通知历史：实发 {len(sent)} 条，抑制 {len(suppressed)} 条"
          f"（原始信号 {engine.ledger.count()} 条全部留存）")
    for n in history:
        tag = {"sent": "发 ", "escalation": "急 ",
               "suppressed": "抑 "}.get(n.decision, "?  ")
        print(f"  [{tag}] ts={n.ts:<6} {n.level:<8} {n.title}  —— {n.reason}")


def install_device_recorder(engine) -> list[tuple[str, str]]:
    """记录真正到达设备侧的指令，用于证明没有误复位。"""
    actual: list[tuple[str, str]] = []

    def adapter(device_id, action, payload):
        actual.append((device_id, action))
        return True, "accepted"

    for d in ("SERVO-A1", "CONV-A1", "ROBOT-A1", "VIS-A1"):
        engine.gateway.register_adapter(d, adapter)
    return actual


# ----------------------------------------------------------------------
# A. 交错告警风暴归并
# ----------------------------------------------------------------------
def part_a() -> None:
    hr("A. 交错告警风暴：一分钟数百条 -> 一个有边界的生产事件")
    engine = build_engine()
    signals = json.loads((DATA / "scenario_signals.json").read_text("utf-8"))

    # 危机时刻（60600 前：驱动器 CRITICAL、机器人/输送线/视觉全停）
    engine.ingest_many([s for s in signals if s["ts"] <= 60_600])
    open_incs = engine.open_incidents()
    print(f"危机时刻：{sum(1 for s in signals if s['ts'] <= 60_600)} 条信号，"
          f"归并出存活事件 {len(open_incs)} 个")
    show_report(engine, open_incs[0].id)
    show_notifications(engine, open_incs[0].id)

    # 继续回放恢复、晚到清除、故障反复的完整后半段
    engine.ingest_many([s for s in signals if s["ts"] > 60_600])
    hr("A（续）恢复信号交错到达、晚到清除、故障反复之后")
    print(f"全程原始信号 {engine.ledger.count()} 条，一条未删；"
          f"存活事件 {len(engine.open_incidents())} 个")
    print(f"通知判定累计 {len(engine.notifications.history())} 条"
          f"（含抑制留痕），其中实发 "
          f"{len(engine.notifications.sent())} 条")
    inc = engine.incidents["INC-0001"]
    print(f"事件最终状态={inc.state}，活动证据={inc.close_blockers() or '无'}，"
          f"剧本卡在 "
          f"{[s['step_id'] for s in engine.stuck_steps('INC-0001')] or '无'}")
    late = [n for n in engine.notifications.history()
            if "晚到" in n.title]
    print(f"晚到恢复信号通知 {len(late)} 条（仅告知，不关闭任何事件）")
    # 台账可分别追溯：直接归集的信号 original==final
    recs = engine.ledger.all()
    robot_rec = next(r for r in recs if r.signal.device_id == "ROBOT-A1"
                     and r.signal.code == "E4105")
    print(f"追溯样例：信号#{robot_rec.signal.seq} "
          f"{robot_rec.signal.device_id}:{robot_rec.signal.code} "
          f"原始事件={robot_rec.original_incident_id} "
          f"最终事件={robot_rec.final_incident_id} "
          f"合并链路={robot_rec.merged_via or '（直接归集，无合并）'}")


# ----------------------------------------------------------------------
# B. 剧本化处置 + 三个安全证明
# ----------------------------------------------------------------------
def part_b() -> None:
    hr("B. 处置剧本：许可门控 / 撤销收权 / 迟到回调不误复位")
    engine = build_engine()
    actual = install_device_recorder(engine)

    def sig(ts, device, code, payload=None, severity=None):
        out = {"ts": ts, "device": device, "code": code, "payload": payload or {}}
        if severity:
            out["severity"] = severity
        return out

    # 1) 驱动器故障 -> 剧本自动挂载，但无许可，s1 卡住
    engine.ingest(sig(1000, "SERVO-A1", "E1001", {"axis": "X1"}))
    # 2) 下游各单元告警沿拓扑归到同一事件（严重度随后升级）
    engine.ingest(sig(3000, "ROBOT-A1", "E4105"))
    engine.ingest(sig(3100, "CONV-A1", "E3002"))
    engine.ingest(sig(3200, "VIS-A1", "W5203", {"station": "VS1"}))
    engine.ingest(sig(3300, "SERVO-A1", "E1002", {"axis": "X1"},
                      severity="critical"))

    show_report(engine, "INC-0001")

    hr("B1. 安全签发 power 许可：STO 才允许下发")
    engine.grant_permit("unit", "cell-A", "power", 4000,
                        reason="中央控制室授权安全转矩断开")
    show_report(engine, "INC-0001")
    sto_dispatch = engine.runs["INC-0001"].run_of(
        "s1_safe_torque_off").dispatch_id

    hr("B2. STO 回调成功 -> 人工现场检查")
    v, _ = engine.handle_callback(
        dispatch_id=sto_dispatch, instance_id="RUN-INC-0001",
        step_id="s1_safe_torque_off", success=True, ts=5000,
        detail="STO 完成，动力切断")
    print("STO 回调裁决:", v)
    engine.complete_manual_step(
        "INC-0001", "s2_field_inspect", actor="王钳工",
        team="maintenance", note="编码器线缆松动，已紧固", ts=6000)

    hr("B3. 证据全部恢复 + 人工确认 + reset 许可 -> 复位下发")
    engine.ingest(sig(6100, "ROBOT-A1", "C4106"))
    engine.ingest(sig(6200, "VIS-A1", "C5204", {"station": "VS1"}))
    engine.ingest(sig(6300, "CONV-A1", "C3002"))
    engine.ingest(sig(6400, "SERVO-A1", "C1001", {"axis": "X1"}))
    engine.acknowledge("INC-0001", actor="李值守", team="shift-A",
                       reason="现场修复完成，确认可复位", ts=6500)
    engine.grant_permit("unit", "cell-A", "reset", 6600,
                        reason="复位授权")
    show_report(engine, "INC-0001")
    s3 = engine.runs["INC-0001"].run_of("s3_reset_drive")
    reset_dispatch = s3.dispatch_id

    hr("B4. 安全证明①：许可撤销后，复位成功回调迟到 -> 仅影子留痕")
    engine.revoke_permit("unit", "cell-A", "reset", 7000,
                         reason="安全员进入围栏核查，撤销复位许可")
    verdict, audit = engine.handle_callback(
        dispatch_id=reset_dispatch, instance_id="RUN-INC-0001",
        step_id="s3_reset_drive", success=True, ts=8000,
        detail="驱动器报告复位完成（迟到）")
    print(f"回调裁决 = {verdict}；审计动作 = {audit.action}")
    print(f"步骤状态仍为 {s3.state}，控制权 = "
          f"{engine.incidents['INC-0001'].control_owner}")
    # 到了超时点：接管后超时也不自行补偿
    engine.tick(13_000)
    print(f"超时点后步骤状态 = {s3.state}（{s3.wait_reason}）")
    restart_sent = [a for a in actual if a[1] == "restart_line"]
    print(f"设备侧实际收到 restart_line 指令数: {len(restart_sent)} "
          f"（期望 0：未夺回控制权、未复产）")

    hr("B5. 安全员撤离并重新签发许可、人工交还 -> 受控重试复位")
    engine.grant_permit("unit", "cell-A", "reset", 14_000,
                        reason="围栏清空，重新授权复位")
    engine.handback("INC-0001", actor="李值守", team="shift-A",
                    reason="现场确认安全，交还自动侧", ts=14_500)
    s3 = engine.runs["INC-0001"].run_of("s3_reset_drive")
    print(f"交还自动侧后 s3 重新走许可裁决：state={s3.state}，"
          f"新 dispatch={s3.dispatch_id}（旧指令身份未被复用）")
    engine.handle_callback(
        dispatch_id=engine.runs["INC-0001"].run_of("s3_reset_drive").dispatch_id,
        instance_id="RUN-INC-0001", step_id="s3_reset_drive",
        success=True, ts=15_000, detail="复位完成")

    hr("B6. start 许可下发 -> 复产回调成功 -> 进入观察期")
    engine.grant_permit("unit", "cell-A", "start", 15_500,
                        reason="复产授权")
    s4_dispatch = engine.runs["INC-0001"].run_of("s4_restart_line").dispatch_id
    engine.handle_callback(
        dispatch_id=s4_dispatch, instance_id="RUN-INC-0001",
        step_id="s4_restart_line", success=True, ts=16_000,
        detail="线体复产")
    show_report(engine, "INC-0001")

    hr("B7. 安全证明②：观察期内故障反复 -> 事件重开，剧本不自动重跑")
    before = len(engine.gateway.log)
    engine.ingest(sig(20_000, "SERVO-A1", "E1001", {"axis": "X1"}))
    inc = engine.incidents["INC-0001"]
    print(f"事件状态={inc.state}，活动证据={inc.close_blockers()}")
    print(f"复发后新增设备指令数: {len(engine.gateway.log) - before}（期望 0）")
    print("剧本步骤保持完成态，等待人工重新裁决：")
    show_report(engine, "INC-0001")

    hr("B8. 安全证明③：人工结案后晚到的恢复信号不得改动事件")
    engine.take_control("INC-0001", actor="李值守", team="shift-A",
                        reason="故障反复，转人工彻底检修", ts=21_000)
    engine.close_incident("INC-0001", actor="维修班长", team="maintenance",
                          reason="更换驱动器并验收，结案", ts=30_000)
    engine.ingest(sig(40_000, "SERVO-A1", "C1001", {"axis": "X1"}))
    print(f"事件状态={inc.state}（仍为 closed），close_reason={inc.close_reason}")
    stale = [a for a in engine.audits if a.action == "clear-ignored-stale"]
    print(f"晚到恢复审计记录: {len(stale)} 条 —— {stale[-1].reason}")
    restart_after = [a for a in actual if a[1] == "restart_line"]
    print(f"全程设备侧 restart_line 实际下发次数: {len(restart_after)}（期望 1，"
          f"即 B6 唯一一次经授权复产）")

    hr("B9. 态势快照（结案存档）")
    show_report(engine, "INC-0001")
    print("\n控制权交接历史：")
    for h in engine.incidents["INC-0001"].history:
        print(f"  ts={h.since_ts:<6} {h.owner:<10} {h.team}/{h.actor}  {h.reason}")
    print(f"\n审计动作序列（共 {len(engine.audits)} 条，节选关键动作）：")
    key_actions = {"incident-opened", "playbook-armed", "command-dispatched",
                   "step-completed", "permit-revoked", "control-taken",
                   "callback-shadow-only", "incident-reopened",
                   "incident-closed", "clear-ignored-stale"}
    for a in engine.audit_log():
        if a["action"] in key_actions:
            print(f"  ts={a['ts']:<6} [{a['team']:<11}] {a['action']:<24} "
                  f"{a['reason']}")


def main() -> None:
    part_a()
    part_b()
    print("\n演示完成。")


if __name__ == "__main__":
    main()

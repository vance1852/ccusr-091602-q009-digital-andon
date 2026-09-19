"""端到端演示：同一驱动器故障引发三个工位的告警风暴，走完处置闭环。

运行：python3 examples/line1_demo.py
输出：事件最终值守视图（根因候选 / 受影响单元 / 控制权 / 卡住步骤 / 通知历史）。
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import ManualClock, Orchestrator  # noqa: E402


def main() -> None:
    clock = ManualClock(1_000.0)
    orch = Orchestrator.from_config_dir(clock=clock)
    orch.grant_permit("P-1", "UNIT-CONV", granted_by="安全员王五", valid_from=0, valid_to=10_000)

    # 驱动器过流，自动化秒级切断输出。
    orch.ingest("DRV_OVERCURRENT")
    inc_id = orch.list_incidents()[0]["id"]
    exe = orch.operations_view(inc_id)["playbook"]["steps"][0]["execution_id"]
    orch.step_callback(exe, "isolate", succeeded=True)

    # 一分钟内三个工位 300 条交错症状告警。
    for _ in range(100):
        clock.advance(0.5)
        for code in ("RBT_STALL", "CNV_JAM", "VIS_REJECT"):
            orch.ingest(code)

    # 值守员处置：确认、转派、现场检查、接管、交还。
    orch.acknowledge(inc_id, operator="张三", shift="甲班", reason="已收到，前往现场")
    orch.reassign(inc_id, "维修二组", operator="张三", shift="甲班", reason="需要机修配合")
    orch.ingest("DRV_OVERCURRENT_CLR")  # 驱动恢复，但症状证据仍在 → 事件不关闭
    orch.complete_manual_step(inc_id, "inspect", operator="张三", shift="甲班", reason="机械无卡阻")
    orch.take_control(inc_id, operator="张三", shift="甲班", reason="手动盘车检查")
    orch.step_callback(exe, "isolate", succeeded=True)  # 迟到回调 → 仅留痕
    orch.revoke_permit("P-1", reason="安全联锁触发")  # 复位步骤被许可挡住
    orch.delegate_control(inc_id, "automation", operator="张三", shift="甲班", reason="盘车完成交还")

    # 症状全部恢复 → 转观察；换发许可后复位执行并完成。
    clock.advance(30)
    for code in ("RBT_STALL_CLR", "CNV_JAM_CLR", "VIS_REJECT_CLR"):
        clock.advance(1)
        orch.ingest(code)
    orch.grant_permit("P-2", "UNIT-CONV", granted_by="安全员王五", valid_from=0, valid_to=20_000)
    reset = orch.operations_view(inc_id)["playbook"]["steps"][2]
    orch.step_callback(reset["execution_id"], "reset", succeeded=True)
    orch.close(inc_id, operator="张三", shift="甲班", reason="故障排除，恢复生产")

    view = orch.operations_view(inc_id)
    print(f"事件 {view['id']}  状态={view['state']}  控制权={view['control_owner']}  "
          f"信号={view['signal_count']} 条")
    print("\n== 根因候选 ==")
    for c in view["root_cause_candidates"]:
        print(f"  {c['device']} ({c['unit']}) score={c['score']}  {c['rationale']}")
    print("\n== 受影响单元 ==")
    for u in view["affected_units"]:
        print(f"  {u['unit']}: {', '.join(u['devices'])} active={u['active']}")
    print("\n== 通知历史（前 6 条 + 统计）==")
    for n in view["notifications"][:6]:
        print(f"  [{n['status']:10s}] {n['kind']:16s} {n['message']}")
    sent = sum(1 for n in view["notifications"] if n["status"] == "sent")
    suppressed = sum(1 for n in view["notifications"] if n["status"] == "suppressed")
    print(f"  ... 共发送 {sent} 条，抑制 {suppressed} 条")
    print("\n== 剧本 ==")
    for s in view["playbook"]["steps"]:
        print(f"  {s['step_id']:8s} {s['state']:10s} {s['name']}")
    print("\n完整视图已写入 /tmp/andon_view.json")
    Path("/tmp/andon_view.json").write_text(
        json.dumps(view, ensure_ascii=False, indent=2), encoding="utf-8"
    )


if __name__ == "__main__":
    main()

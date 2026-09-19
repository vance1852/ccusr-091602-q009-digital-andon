# 数字安灯事件编排

把设备原始告警归并为可处置的生产事件，并在安全许可约束下推进处置步骤。原始信号不会因抑制通知、事件关联或结案而删除。

`domain_contract.json` 给出事件、处置剧本和控制权状态。设备依赖关系有生效版本，自动回调必须携带执行实例与步骤标识。

## 组成

```
config/topology.json    设备依赖拓扑（带 version / effective_from 生效版本）
config/alarm_map.json   告警码 → 设备 / 严重度 / 事件类型 / 关联组 / 根因或症状
config/playbooks.json   事件类型 → 处置剧本（前置条件、超时、补偿动作）
app/models.py           领域模型（状态取值与 domain_contract.json 对齐）
app/config.py           配置装载与校验
app/orchestrator.py     归并、抑制、恢复语义、剧本引擎、许可与控制权、审计、查询
app/clock.py            可注入时钟（测试用 ManualClock 确定性推进）
examples/line1_demo.py  端到端演示：python3 examples/line1_demo.py
```

## 核心规则

**归并与信号保留**
- 故障信号按 `correlation_group` + 关联时间窗（默认 300s）归并成有边界的事件；结案或超窗后的新故障开新事件。
- 每条原始信号都落库并挂在事件上，抑制、合并、结案都不删信号。
- 根因候选按拓扑排序：是其他告警设备上游依赖的设备得分更高，并附中文理由。

**通知**
- 同一事件在抑制窗口（默认 60s）内的重复通知被抑制，但全部留痕（`status=suppressed`）。
- 严重度升级（超过已通知过的最高级别）立即放行，不受窗口约束。

**恢复语义**
- 恢复信号只清除与自己同键的证据；仍有其他证据支撑的事件不得转观察、不得关闭。
- 全部证据清除 → 事件转 `monitoring`（观察），结案只能由值守员执行。
- 晚到 / 重复的恢复信号只留审计（`late_recovery`），不改变任何状态；结案后的恢复不会重开事件。

**剧本与安全**
- 步骤状态：`pending → running/waiting → compensating → completed/failed`（见契约）。
- 自动步骤只在安全许可有效时执行；许可撤销会中止运行中的自动步骤并执行补偿。
- 前置条件（如 `evidence_clear`）不满足、许可无效、控制权不在自动化时，步骤保持 `pending` 并记录全部阻塞原因（出现在“卡住的步骤”里）。
- 超时 → 步骤失败 → 执行补偿动作；补偿本身需要许可而许可无效时，步骤停在 `compensating` 直到许可恢复。
- 自动回调必须携带执行实例与步骤标识；过期的执行实例（超时、重启、接管后）回调仅留痕（`ignored_callback`），不会改写状态，更不会误复位设备。

**控制权**
- 人工接管（`take_control`）后，运行中的自动步骤挂起，后续自动回调仅留痕，自动化不能夺回控制权；只能由值守员 / 安全员显式 `delegate_control` 交还。
- 确认、转派、暂停、恢复、接管、交还、结案都必须记录操作人、班组和理由；结案要求证据已清（或 `force=True` 并留痕）。
- 关联事件合并（`link_incidents`）后，各事件的信号与审计仍可分别追溯。

## 值守视图

`orchestrator.operations_view(incident_id)` 一次给出：事件状态与严重度、根因候选、受影响单元、当前控制权、剧本进度与卡住的步骤（含原因）、通知历史（含被抑制记录）、全部原始信号、审计留痕、合并关系。

## 运行

```bash
python3 -m unittest discover -s tests -v   # 31 项检查
python3 examples/line1_demo.py             # 端到端演示
```

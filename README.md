# 数字安灯事件编排（digital-andon-orchestrator）

把产线设备在故障瞬间涌出的海量原始告警，归并成**有边界、可处置、可追溯**的生产事件，
并在**安全许可**约束下推进带前置条件、超时与补偿的处置剧本。

设计底线：

- **每条原始信号永久留存**——抑制通知、关联合并、结案都不删除信号；
- **严重度升级立即穿透**任何抖动抑制；
- **恢复信号只精确熄灭对应证据**——晚到、错轴、结案后到达都不能关闭仍被其他证据支撑的事件；
- **自动步骤只在安全许可有效时下发**，联锁优先于许可；
- **人工/安全接管后，后续自动回调只留痕（shadow），永不夺回控制权、永不复位设备**；
- 值守员的确认、转派、暂停、交还、结案全部记录**班组、人员、理由**。

## 运行

```bash
python -m unittest discover -s tests -v   # 29 个测试
python -m app.demo                        # 端到端演示（含三个安全证明）
```

无第三方依赖，仅使用 Python 3.11 标准库。

## 仓库数据

| 文件 | 内容 |
| --- | --- |
| `data/devices.json` | **版本化**设备依赖拓扑（`depends_on` 有向图，按信号时间戳选版本） |
| `data/alarms.json` | 告警映射：事件类型、默认严重度、跨设备关联键 `group_by`、抖动窗口、`clearance_for` 清除对应、绑定剧本 |
| `data/playbooks.json` | 处置剧本：有序步骤（自动/人工）、前置条件、许可类别、超时与补偿 |
| `data/scenario_signals.json` | 一分钟内交错的告警/恢复/反复信号（17 条） |
| `domain_contract.json` | 事件状态、剧本步骤、控制权三类离散取值，启动时校验一致性 |

示例拓扑：`SERVO-A1（主驱动器）→ CONV-A1（输送线）→ VIS-A1（视觉站）`，
`ROBOT-A1` 同样依赖驱动器。驱动器故障时机器人 STO、输送线堵转、视觉触发超时
都会沿依赖传播，被归为同一事件，根因候选评分为驱动器。

## 模块结构

```text
app/model.py         契约状态、不可变 Signal/AuditEvent、严重度、事件状态机
app/topology.py      版本化拓扑、上下游传递闭包、受影响单元
app/alarms.py        告警映射与关联键提取
app/incidents.py     事件聚合：证据生命周期、根因评分、合并、控制权、状态机
app/notifications.py 信号台账（不删除）+ 通知历史（抖动抑制/升级穿透）
app/safety.py        安全许可（global/unit/device × action）与硬联锁
app/playbooks.py     剧本定义与执行实例（pending/running/waiting/compensating/…）
app/gateway.py       设备指令网关：dispatch_id、回调身份校验、挂起登记
app/engine.py        编排内核：ingest / tick / handle_callback / 人工动作
app/bootstrap.py     从仓库数据装配引擎并校验契约
app/demo.py          端到端演示
```

## 核心语义

### 1. 告警 → 有边界事件（证据模型）

- 每条 `raise` 产生/激活一条**证据**，键为 `设备|代码|关联维度`（如同一个 `axis=X1`）；
- 同指纹短时重复落在 `dedup_window_ms` 内只累加 `raised_count`，通知被抑制并留痕；
- `clear` 按 `clearance_for` + 设备 + 关联键子集**精确熄灭**证据；
- 事件聚合规则：同事件类型 +（同设备历史 / 共享关联维度 / 新设备位于某事件根因设备的拓扑下游）；
  先独立打开、后被传播关系确认同源的事件走**关联合并**，保留父子链路；
- 事件只在**活动证据全部熄灭**且（无剧本 / 剧本走完并度过观察期）后自动结案；
- 信号台账同时记录 `original_incident_id`、`final_incident_id`、`merged_via`，合并后仍可分别追溯。

### 2. 根因候选评分

```
score = 能向下游解释的其他活动证据设备数 × 3
      + 共享关联维度的其他证据数 × 2
      + 该设备自身活动 raise 次数
```

只有映射中 `root_cause: true` 的设备可作候选（机器人 STO、视觉超时等下游症状不参与）。

### 3. 处置剧本

- 事件类型绑定剧本（映射可用 `playbook` 覆盖），`auto_arm: false` 的剧本（如急停）仅人工接管后激活；
- 自动步骤依次过：**前置条件**（如 `fault_active` / `fault_cleared` / `acknowledged` / `no_interlock`，
  每次推进重新求值）→ **控制权检查** → **安全许可+联锁裁决** → 网关下发；
- 下发后进入 `running`，回调必须携带 `dispatch_id + instance_id + step_id`，错身份/重复/未知一律丢弃
  （且不会吞掉合法挂起指令）；
- 超时：原挂起指令身份注销（其迟到回调随之被忽略）→ 进入 `compensating` 执行补偿（如动力制动、主回路隔离、
  复产失败回 STO）；补偿本身也要许可，许可缺失时停在 `compensating` 安全等待并升级通知；
- 人工步骤必须由值守员回填完成。

### 4. 控制权（不可自动夺回）

`automation → operator/safety` 的交接全程留痕。以下任一成立时，设备回调只记 `callback-shadow-only`，
不改变步骤、不复位、不复产：

- 事件当前在人工/安全控制下；
- 指令下发时间早于当前控制权生效时间；
- 事件已结案。

`revoke_permit` 会联动把受影响事件收归 `safety` 控制；在飞指令超时后也只交人工，不自行补偿。

### 5. 态势查询

`engine.situation_report(incident_id)` 一次给出：根因候选、受影响单元、设备与活动证据、
当前控制权与交接史、剧本各步骤状态、**卡住的步骤及原因**、通知历史、合并子事件与信号序列。

## 安全证明（见 `python -m app.demo` 的 B4/B7/B8）

1. **许可撤销 + 回调迟到**：复位指令下发后许可被撤、控制权收归 safety，迟到的“复位成功”回调裁决为
   `shadow`，无 `restart_line`，超时也不自动补偿；重新授权并人工交还后才用**新指令身份**受控重试；
2. **故障反复**：观察期内驱动器再报，事件回到 `mitigating`，已完成剧本不自动重跑、零新指令；
3. **结案后晚到恢复**：人工结案后到达的 `C1001` 记录 `clear-ignored-stale`，事件保持 `closed`，
   全程仅一次经授权的 `restart_line`。

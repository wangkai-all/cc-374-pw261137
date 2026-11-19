# Pointwise-Restart：三表数据完整性管道

一批数据包含 **账户（accounts）、关系（relationships）、交易（transactions）** 三张表。
错误账户可能被多条交易/关系引用。本项目实现接收服务、校验器、发布目录三者协作的完整管道，
**绝不把坏行隔离后就宣称剩余数据完整可用**：任何被排除的行都带有错误原因、依赖传播链和
修正回接指引；发布集合经独立校验保证"零无来源孤立引用"。

仅使用 Python 3.11 标准库（sqlite3 / http.server / csv / zipfile / hashlib），零第三方依赖。

## 运行

```bash
# 端到端命令行演示（接收→校验→发布→两种崩溃→恢复→单点修正重放→全批拒收）
python3 -I src/cli.py demo

# 网页仪表盘（默认 127.0.0.1:8000；--reset 清空工作区做干净演示）
python3 -I src/serve.py --reset --port 8000

# 独立核对一个已发布版本（校验和 + 引用闭合性）
python3 -I src/cli.py verify workspace/releases/v1

# 按键查询：行状态、错误码、污染链，以及"若修正此行会重验证哪些行"的反向闭包
python3 -I src/cli.py query --batch-id BATCH-2026-ALPHA --key ACC-1002

# 丢弃网页/工作副本上的修正，从不可变源 CSV 重新接收（缓存与已发布版本保留）
python3 -I src/cli.py rereceive --batch-id BATCH-2026-ALPHA

# 测试
python3 -I -m unittest discover -s tests -v      # 33 个用例
```

## 虚构数据中的问题（data/batches/BATCH-2026-ALPHA）

| 根因 | 位置 | 级联影响 |
|---|---|---|
| 账户余额为负 | ACC-1002 (L2) | REL-1001、REL-1004、T-1001、T-1003、T-1008 被污染 |
| 币种枚举非法 XBT | ACC-1008 (L8) | — |
| 主键重复 | ACC-1011 (L11/L12) | 两行均隔离；REL-1003、T-1007 被污染 |
| 主键缺失 | accounts L13 | — |
| 引用不存在账户 | REL-1007/1008、T-1010/1011 | 直接 E_FK_MISSING |
| 关系强度越界 1.50 | REL-1009 | T-1013 被污染 |
| 交易金额为负 | T-1014 | 直接错误 |
| 交易引用不存在关系 | T-1012 → REL-9001 | 直接错误 |

首批 38 行：12 条内在错误结论、9 条污染结论、5 条悬挂引用。

## 两种可接受策略（选择必须说明删了什么、怎样接回）

1. **`reject_batch` 全批拒收**：不发布任何行，38 行全部进入隔离包，交接清单逐行给出修正与回接步骤。
2. **`retain_subset` 保留闭合子集**（默认）：只发布 VALID 行。污点不动点传播已保证
   发布子集中没有任何行引用子集外的键；发布前 `policy._closure_violations` 再做一次防御性检查，
   若出现孤立引用直接抛错而不是发布。

隔离包 `quarantine-vN.zip` 内每个隔离行额外带三列：
`_quarantine_reason`（错误码或 TAINT）、`_dependency_chain`（完整依赖路径）、`_remediation`
（如何在源系统修正并重新装载），并附 `handback-manifest.json` 与 `CHECKSUMS.sha256`。

## 单点修正与最小重放

- 每行内容经规范化哈希（`Row.content_hash`）标识。**字段级内在校验结果按哈希缓存**并持久化到
  SQLite；修正一行后重放，未变行全部命中缓存（演示：37 个哈希中 36 命中、1 个重算）。
- 图级检查（重复键、外键、污点闭合）**永不缓存**，每次全量重算，因此修正能正确改变传播结果。
- 重放范围 = 被改行在引用图上的传递反向闭包（演示：修 ACC-1002 一行，6 行重验证、32 行复用），
  受影响的交易 T-1001/T-1003/T-1008 自动恢复为 VALID。
- 每次发布生成**不可变新版本**（v1、v2…），旧版本永不覆盖。

## 崩溃与恢复（状态机持久化于 SQLite）

`RECEIVED → VALIDATING → VALIDATED → PUBLISHING → PUBLISHED`，两个模拟崩溃点：

- **校验完成、发布前崩溃**（`CRASHED_PRE_PUBLISH`）：校验结论已落库，恢复时直接发布，无需重校验。
- **发布过程中崩溃**（`CRASHED_DURING_PUBLISH`）：文件只写入隐藏的 `staging/`，提交靠单次原子
  `os.rename`；崩溃后 live 发布指针绝不前进。恢复时先校验暂存区校验和，再原子提交；重复恢复为
  幂等空操作，暂存区被篡改则拒绝恢复。

## 网页（web/static/index.html，纯 vanilla JS + 内联 SVG）

- 传播链图：矩形=账户、菱形=关系、椭圆=交易（形状做次级编码）；红=根因、橙=污染、绿=有效；
  点击节点展示完整 root→via 依赖路径。调色板经 dataviz 校验器在明暗两种表面下通过 CVD/对比度检查。
- 行级修正表单：改一处 → 仅重放受影响闭包，显示缓存命中/未命中与重放范围。
- 行查询框：输入任意主键（如 ACC-1002、T-1001）查看状态、错误码、污染链与修正影响闭包；
  重复键会返回全部同名行。
- "Reset working copy" 按钮调用重新接收接口，从不可变源 CSV 还原工作副本，已发布版本保留。
- 崩溃模拟器两个按钮 + Resume；下载中心提供每个版本的 release/quarantine 两个 zip；
  交接清单可按版本查看；明暗主题切换。

## 目录

```
data/batches/          虚构三表 CSV（不可变证据，管道从不改写源文件）
src/pointwise/         models/loader/validator/policy/publisher/store/pipeline/web
src/cli.py             命令行（含 demo、verify）
src/serve.py           网页入口
web/static/index.html  单页仪表盘
tests/                 33 个 unittest（管道 24 + HTTP 9）
workspace/             运行产物（gitignore）：pipeline.db、batches 工作副本、
                       releases/vN、quarantine/vN、staging、downloads/*.zip
```

## 不变量

- 发布集合内每条引用都解析到集合内的行（无孤立引用），由 `verify` 独立复核。
- 行不会被静默丢弃：发布数 + 隔离数 = 接收行数；每个隔离行有原因、链、修正指引。
- 源 CSV 哈希在接收时固定并写入清单；篡改发布文件会被 `CHECKSUMS.sha256` 检出。

# N1.1：字段与组合声明校验

日期：2026-09-23。完成声明清单校验这个独立子包，**不是完整 N1.1 / N1.6 或任何新协议验收**。不改 Rust 运行时、生产配置、schema14、Invoke v5 或依赖锁。

## 已实现接口

```sh
uv run --project scripts --locked vcore-scripts check protocol-coverage --catalog-only
```

当前只提供显式 `--catalog-only` 模式。默认读取本仓库 `tests/protocols/`；`--catalog-dir` 可选择检查副本。没有case/result检查或隐式阶段签收模式。

- 校验冻结的145字段和69组合家族ID，不依赖可自行修改的 `field_count` 放行缺项；稳定ID调整需审查验证器契约与声明的对应变更。
- 校验JSON schema版本/结构、重复键、声明状态、来源/字段/对端/override引用及重复引用、协议范围与适用性、阶段与子包归属、非空观察项和正向模式维度。
- 原生未证明类别必须保留阻塞说明；契约拒绝类别必须保留条件和拒绝阶段；8种协议/64个有序上游组合声明不能缩水。
- 来源只能是无凭据/查询参数的HTTPS链接或无路径逃逸的相对路径；只检查声明，不联网、读取来源文件或执行引用。无效输入只输出诊断，不回显JSON内容。
- 退出0表示 `status: VALID`，行为状态始终 `NOT RUN`；无效清单退出1，缺少显式模式退出2。字段与组合声明中嵌入PASS等运行状态会失败。

145字段不等于145个测试，69家族也不等于69个可执行case。本工具不求值自然语言条件、不判断来源是否真实可达/权威、不展开笛卡尔积，也不把已有实验报告导入为正式字段PASS。生产支持仍由 `docs/config.yaml` 定义。

## 验证与输入绑定

测试通过现有 CLI 的参数、返回码与输出进行，不 mock 内部校验器。先记录命令缺失的RED，再逐项补齐漏项、重复/未知ID、声明伪PASS、引用、原生缺口、JSON与类型错误、归属、来源和模式维度等负例；每项修复后重跑。默认目录还在临时工作目录中验证，未依赖相邻研究源码。

- 被测父提交：`69b230adcb616f13264eb5f20722a234e9e8980c` 加本轮脚本源码/测试差分；提交发生于测试后。
- 差分 SHA-256：`ed535718d735820404c5b61ed46a6afcbb23d22fa0e44a2c5de584296099e6f6`。提交后重算命令：`git diff 69b230a HEAD -- scripts/src scripts/tests | shasum -a 256`；不包含说明文档。
- 清单未改：fields SHA-256 `194695f42029f262d3e87ba2744385c1416b6681eb1eae555b23414309f880aa`；combinations SHA-256 `447e3d58a55ffa32e32f028df9647853b621246a450a8410aa66460b06247da9`。
- 环境：macOS 27.0 ARM64、Python 3.14.7、ruff 0.15.22；未新增第三方依赖。

| 实际命令 / 范围 | 结果 |
| --- | --- |
| `python -m unittest discover -s scripts/tests`（通过 `uv run --project scripts --locked`） | 57项PASS：15项新增CLI测试，42项既有脚本回归 |
| `vcore-scripts check protocol-coverage --catalog-only` | 退出0；145字段、69组合，`VALID / NOT RUN` |
| `vcore-scripts check protocol-coverage --help` | 新入口及两个参数可用 |
| 缺少 `--catalog-only`、错误清单 | CLI测试确认分别退出2/1，无成功JSON或伪行为PASS |
| scripts ruff check / format check | PASS |
| `vcore-scripts check tls-dependencies` / `check c-header` | 既有CLI入口回归PASS，依赖图及接口身份不变 |
| `git diff --check` | PASS |

原始RED及最终日志位于 `target/interop/runs/n1-catalogs-20260923/`。`scripts-tests.log` SHA-256为 `590d8f6f78e2a59934f0cbd7de66eac500911013c119906e5238002df49a8f39`，实际CLI输出 `catalogs.json` SHA-256为 `eab244fe7debd7806f39e65b1c97f3edbe009ad0f49a2789e5b353ad117d2161`。它们只证明本轮静态工具行为，不作为协议互通结果。

## 剩余门禁

N1.1的生产配置/limits登记/资源观察，N1.2–N1.5的共享机制，以及N1.6的具体case清单、统一互通编排、逐字段断言、run/peers/resources结果与阶段覆盖检查均未在本子包完成。当前不接受 `--stage` / `--run-dir`，不创建空壳cases或占位PASS。

本轮没有重新运行Rust测试、跨平台构建、外部对端、真机、Windows原生、远端CI或长测；前一个独立依赖子包的结果仍按[原始输入与证据](N1-foundation-dependencies.md)保留，不转记为新harness验收。本轮仅本地提交，无push。

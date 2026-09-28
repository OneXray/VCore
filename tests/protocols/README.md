# 协议验证输入

生产字段只以 [config.yaml](../../docs/config.yaml) 和协议契约为准。
本目录保留真实执行需要的输入，不维护开发阶段规划、候选库实验或重复 JSON 清单。

- foundation-cases.json：尚未替代的基础/Trojan 稳定证据标识与断言。旧服务端编排
  未全容器化，不作为可执行宿主入口；本地基础测试使用 check core。
- 其他可执行用例由 scripts/src/vcore_scripts 下各协议 catalog/definitions 生成，
  protocol_evidence.load_manifest 统一校验。用例 ID 以协议或验证用途为前缀，
  分组使用 tcp、udp、transports、lifecycle 等能力名称，不绑定开发阶段。
- limits.json：局部资源上限及边界 case；Rust 测试对照真实常量。
- encryption-crypto.json 与 encryption-vectors：独立官方 Go 原语生成的密码向量，
  被生产模块的确定性测试直接使用。
- stream_probe.rs：旧基础消费者仍有引用，保留编译；不是四个已删除的独立 spike。

```sh
uv run --project scripts --locked vcore-scripts check protocol-coverage --catalog-only
uv run --project scripts --locked vcore-scripts check protocol-interop --suite vless --list
uv run --project scripts --locked vcore-scripts check protocol-interop --suite vless
uv run --project scripts --locked vcore-scripts check protocol-coverage --suite vless --run-dir target/interop/runs/<run-id>
```

catalog-only 仅 VALID / NOT RUN。运行记录的原始事件、命令/退出、源/锁文件/对端身份、
hash、所有者清理和资源快照共同决定结果；空、部分、重复、改源、超时、CFG-only 或
未清理都不能 PASS。保留完整通过与原始失败，不拼接旧报告。case 子集不签收整套。

Mihomo 是默认 listener；缺口由官方 Xray、V2Ray、Hysteria、ssserver 补验。
共享字段按实际整个模式选择对端，XHTTP 两腿须到同一原生会话表；分层网关不是单端
原生支持。对端最新下载策略与命令见 [scripts](../../scripts/README.md)；
所有服务端遵守[隔离规则](../../docs/testing-isolation.md)。

integration 保留七协议有序两跳、100 次生命周期、100 轮 40-flow 重建、1800 秒持续
流量和实际 HY2 跳跃。短测不代替长测，编译不代替物理设备；[验收边界](../../docs/acceptance.md)
单独列出对端限制、参照差异和未完成发布条件。

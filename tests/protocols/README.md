# 核心协议回归输入

生产字段以 [config.yaml](../../docs/config.yaml) 和协议契约为准。本目录只保留
VCore 纯核心回归直接使用的独立输入，不包含容器 catalog、消费者或测试编排。

- `limits.json`：局部资源上限、实际常量引用和边界断言；
  `tests/limit_foundations.rs` 直接读取并核对。
- `encryption-crypto.json`：独立官方 Go 原语生成的 Encryption 密码向量；
  `src/outbound/vless/encryption/crypto.rs` 和 `records.rs` 的确定性回归直接使用。
  生成器及外部验证由独立 container-benchmark 工程维护，不能从待测实现重生成期望。

核心检查命令见 [scripts](../../scripts/README.md)。容器协议互通、官方对端、
catalog 和流消费者由独立 benchmark 显式接收 VCore checkout 后执行；
它们不影响本仓库离线检查或平台构建。

输入文件属于受版本控制的测试源，不是每轮产生的测试数据。每轮容器实验仅保留
脱敏文字结论，清理规则见[测试隔离](../../docs/testing-isolation.md)；
行为、互通和设备的证据边界见[验收范围](../../docs/acceptance.md)。

# N0-D：受控数据报上的 Hysteria2 最小互通

日期：2026-09-22。**本页保存当日 auth/stream、DIRECT/SOCKS5 UDP 和 protect 子门禁 PASS，以及原生半关闭 FAIL。** 当时官方 Hysteria 单状态多端口入口、Xray H3 入口尚未执行；2026-09-23 的后续结果见 [QUIC 原生入口](N0-quic-entries.md)。本文不开放生产字段，不签收 N5/N6，旧失败不被后续通过覆盖。

## 输入与对端身份

- 分支 `feat/next-protocols`；被测父提交 `06f6e5beef3ff68edee9da96f3ed282a6764fb72`，加本次自有 [独立实验](../../../tests/protocols/spikes/hysteria2/README.md)。提交发生在测试之后。
- 生产源码仍为 N0 起点 `bbe5100abcf07b1158f86cff39cd835e1f32ccf9` 的内容；主 Cargo.toml / Cargo.lock 未改。主锁 SHA-256 `64866bfff397559e3b5e9cb03094cfb229ccaf28ae2c8fae0a549d3a9106f8e2`。
- macOS 27 ARM64、Rust/Cargo 1.98.1、uv 0.12.17；证书由本机 LibreSSL 3.3.6 的 `openssl req` 生成，只用于回环夹具。
- 独立 workspace 使用 Quinn 0.11.12、quinn-proto 0.11.18、h3 0.0.8、h3-quinn 0.0.10。唯一 rustls 0.23.43 固定到现有 `df261c84cbac4f708e63ac8644ce70daa90d771c`，TLS ring，官方 tokio-rustls 0.26.4；未使用新增混合 REALITY fork 提交或 AWS-LC。
- 实验 lock SHA-256 `26114362039efecee8d9253a0aab6f2074e82b4e1f177d85d4ca3f6326aaba58`。候选依赖许可/feature 背景沿用 [N0 数据报报告](N0-datagram.md)，不是发布依赖审计替代品。

每次运行重新下载官方 latest，实际版本由可执行文件查询；无 GitHub API、本地编译或下载失败后的缓存回退。hash 是下载内容身份，不冒称官方签名验证。

| 对端 | 本轮版本 | 二进制 SHA-256 |
| --- | --- | --- |
| [Mihomo latest](https://github.com/MetaCubeX/mihomo/releases/latest/download/version.txt) | v1.19.31，darwin arm64，Go 1.26.8，with_gvisor | `fae1f37e28ee53fcf5be7a8bb121099db1fe442e44205734ed49c62579364090` |
| [Hysteria latest](https://github.com/HyNetworks/hysteria/releases/latest/download/hysteria-darwin-arm64) | v2.12.3，commit `e1366b173ccf5706e1e4630fe8aa654a4b574085`，darwin arm64 | `9065dc5dc9cd75f7ba881f481e8cb77e7eae17139460ca09d399682ca6fad443` |

Mihomo 优先验证其实际 listener 能力；仅 `disableUDP` 协商负能力使用官方 Hysteria。没有因为 Mihomo 超时就换服务器抵扣该失败。

## 已执行结果

最终正常验证运行开始于 **06:11:51 UTC**；8/8 case PASS。目标均为回环 TCP echo，验证服务器先发、双向 65,536-byte 内容、14-byte 尾部标记及 EOF；不是正式 10 MiB/双栈/域名全集。

| Case | 结果 / 具体观测 |
| --- | --- |
| `mihomo-direct` | HTTP/3 status 233，UDP=true；TCP 内容、服务器先发、FIN 后尾部响应与 EOF 正确；protect 1 次 |
| `mihomo-socks5-udp` | 同上，经现有 SOCKS5 UDP ASSOCIATE；独立 Mihomo 上游实例；TCP control 与 UDP 各 protect 1 次 |
| `mihomo-wrong-password` | `auth_rejected`，未打开业务流；目标连接 0、业务字节 0 |
| `mihomo-wrong-name` | 明确信任测试证书但名称不符；本地 QUIC crypto error 0x12a / `tls_rejected`；目标连接 0、业务字节 0 |
| `reject-direct` | 第 1 次 protect 拒绝；QUIC 数据报发送计数 0，目标连接/业务字节 0 |
| `reject-socks-control` | SOCKS TCP control 的第 1 次 protect 拒绝；未创建 Quinn driver；目标连接/业务字节 0 |
| `reject-socks-udp` | TCP control 已成功，第 2 次 protect 拒绝 UDP；QUIC 数据报发送计数 0，目标连接/业务字节 0 |
| `hysteria-udp-disabled-tcp` | 官方 `disableUDP: true`，auth 233 / UDP=false；正常 TCP 回显和服务器 EOF 正确；**不声称该对端支持半关闭** |

三个成功数据例子的 BBR factory 均实际构造 1 次；密码/证书失败不回退其他路径。拒绝探针使用真实 Dialer socket 路径上的合成 protect 回调，不等于 Android VPN/Windows 真机验证。

正常结束与负例均执行已拥有资源的清理。H3 task 完成、Quinn endpoint idle、数据报 owner join、停止后 `try_send` 拒绝均验证；共用 5 秒清理期限，已启动 driver 的本轮最大清理耗时约 100.4 ms。此处不证明正式 Running Session 的完整 Stop/计数/5 秒静默窗口。

### 最小带宽试验基线，不是带宽字段验收

| 路径 | auth/setup ms | 64 KiB 回显 ms | 收/发队列峰值（包） | 适配队列丢包 |
| --- | ---: | ---: | --- | ---: |
| Mihomo DIRECT | 8.737 | 5.443 | 32 / 20 | 0 |
| Mihomo SOCKS5 UDP | 8.156 | 3.948 | 32 / 20 | 0 |
| Hysteria UDP-disabled / TCP | 7.040 | 4.122 | 32 / 20 | 0 |

这是 Debug、本机回环、单连接的一次观测，未隔离 CPU 调度，不能横比路径性能。`Hysteria-CC-RX: 0` 与测试服务端 ignore-client-bandwidth 配置用于探测模式；只验证公开 BBR `ControllerFactory` 确实安装，不证明 Brutal、速率协商/限速、丢包收敛、pacing 或 N6 带宽门槛。N1 仍须冻结 N6 可判定参数。

## 已定位的失败，不隐藏或抵扣

1. **Mihomo 证书安全路径**：初次把证书放在 listener 数据目录之外，Mihomo 启动 SOCKS 后拒绝 HY2 listener；客户端超时、收包为 0。改为每实例数据目录内的证书，不设置放宽路径检查的环境变量；readiness 同时检查 HY2 启动日志。
2. **端口夹具**：仅检查 TCP 空闲时，SOCKS 的同号 UDP 端口可能已被占用。改为复用现有 `reserve_port` / `exclusive_run`，预留两族 TCP/UDP；没有结束占用该端口的其他进程。修正后重跑全部 case。
3. **实验接收队列**：初版满队列直接丢弃，本机 burst 出现丢包。按 TDD 写 40 包/暂停消费的真实 UDP 用例，先观察 8 包被丢弃的 RED，再改为满队列暂停 receive、消费后唤醒 owner。最终 40 包按序完整收到；原生互通队列丢包为 0。仅修改自有实验 adapter，生产接口不变。
4. **官方 Hysteria 半关闭仍 FAIL**：同一测试先发送 FIN 再读回显，原生端目标收到 65,536 字节，客户端本轮仅收到 44,565 / 65,550 字节，前缀正确，目标端写回失败；错误为 `tcp_data_mismatch`。Mihomo 的该用例通过。官方 Hysteria 正常响应/服务器 EOF 的对照通过，但不能覆盖这项失败。

第 4 项与对应发布源码一致：`copyTwoWay` 等任意一个方向结束即返回，调用方随后同时关闭目标 TCP 与 QUIC stream；`QStream.Close` 还取消读取。这解释了客户端 FIN 后下行被提前结束。没有修第三方、延迟/吞掉 FIN 或把失败改成“预期成功”。[官方 copy.go](https://github.com/apernet/hysteria/blob/e1366b173ccf5706e1e4630fe8aa654a4b574085/core/server/copy.go#L68)、[清理调用](https://github.com/apernet/hysteria/blob/e1366b173ccf5706e1e4630fe8aa654a4b574085/core/server/server.go#L331)、[QStream.Close](https://github.com/apernet/hysteria/blob/e1366b173ccf5706e1e4630fe8aa654a4b574085/core/internal/utils/qstream.go#L43)。

该诊断保留为独立 `--native-half-close` 开关，运行会失败并记录实际字节，不进入正常 8 项 PASS 统计。N6 使用 Mihomo 验证半关闭；原生特有字段的半关闭组合继续记对端限制/未通过，不宣称所有原生组合通过。

## 接口与资源结论

- 使用 VCore 公共 `OutboundConnector::open_datagram`，不在 Quinn 或协议侧偷偷 bind；已有 DIRECT 的 socket 懒创建，因此首次成功发送前不 poll receive。
- 现有 `DatagramTransport` 收发共享 `&mut self`。实验单 owner 用 cancellation-safe receive + 有界发送队列衔接 Quinn；没有锁内 await。32 × 1400-byte 收/发队列和最多一个发送中报文；满发送队列返回 `WouldBlock` 并正确唤醒 poller；接收暂停后消费会唤醒 owner。
- 一个逻辑 peer/连接、一个 writer poller；验证返回来源与发送目的，拒绝超长包和 GSO。固定 QUIC MTU 1200、关闭 MTU discovery；逻辑 local_addr 是未指定地址/0 端口，不冒充物理 socket 地址。多连接公平、真实路径发送预算、其他源族/迁移、资源计数和正式关闭接口仍归 N1。
- HTTP/3 控制连接持续在已拥有 task 中驱动，保留最后一个 `SendRequest` 至业务流结束。TCP 响应按有界长度精确读取，避免临时 buffered decoder 丢失服务器先发数据。认证成功才创建业务 stream。
- TLS 1.3、ALPN h3、测试信任根和名称验证；不使用 skip-cert-verify。有限 QUIC stream/connection window，公开 BBR factory，无私有 TLS/QUIC hook。
- 本例没有 HY2 UDP 编解码/分片、Salamander、端口跳跃、正式复用池、Brutal、Xray H3、图选择或 TUN 集成。

依据：[HY2 协议](https://v2.hysteria.network/docs/developers/Protocol/)、[Quinn AsyncUdpSocket](https://docs.rs/quinn/0.11.12/quinn/trait.AsyncUdpSocket.html)、[h3 connection 驱动要求](https://docs.rs/h3/0.0.8/h3/client/struct.Connection.html)、[Clash-RS 参考实现](https://github.com/Watfaq/clash-rs/blob/39d06a49ccb5c812ed7cd70b3028f3efcebeae6b/clash-lib/src/proxy/hysteria2/outbound/mod.rs)。没有复制其未完成的控制器接线或使用其 TLS fork。

## 验证命令与证据

均从 VCore 根目录执行；完整互通入口见实验 README。

```sh
cargo fmt --manifest-path tests/protocols/spikes/hysteria2/Cargo.toml -- --check
cargo test --locked --manifest-path tests/protocols/spikes/hysteria2/Cargo.toml \
  --target-dir target/interop/n0-hysteria2-build
cargo clippy --locked --manifest-path tests/protocols/spikes/hysteria2/Cargo.toml \
  --target-dir target/interop/n0-hysteria2-build --all-targets -- -D warnings
cargo check --locked --manifest-path tests/protocols/spikes/hysteria2/Cargo.toml \
  --target-dir target/interop/n0-hysteria2-build --target aarch64-apple-ios --all-targets
uv run --project scripts --locked ruff check tests/protocols/spikes/hysteria2/run.py
uv run --project scripts --locked ruff format --check tests/protocols/spikes/hysteria2/run.py
uv run --project scripts --locked python tests/protocols/spikes/hysteria2/run.py --native-hysteria
```

- 自有单元/接口测试 **5/5 PASS**：真实 UDP 往返/来源/预算/发送背压/Stop；饱和接收；TCP framing；超长/截断/拒绝；服务器先发剩余数据。
- 上述 clippy、iOS arm64 all-targets check、Python lint/format PASS。另以 NDK **28.2.13676358 / API 24** 的 `aarch64-linux-android24-clang` / `llvm-ar` 设置 `CC_aarch64_linux_android` / `AR_aarch64_linux_android`，对同一独立 manifest 执行 `cargo check --locked --target aarch64-linux-android --all-targets` PASS，target-dir 为 `target/interop/n0-hysteria2-android-build`。
- 原 N0 datagram 实验回归 **4/4 PASS**；主 `check tls-dependencies` PASS。精简 VCore feature 仍产生既有 97 条 unused/dead-code warnings，没有因此改无关生产代码；spike 自身 `-D warnings` 通过。
- iOS/Android 只有交叉 check，没有设备安装、运行或 Android protect 真机证明；Windows、其他架构与正式协议阶段门槛 NOT RUN。本次不重复宣称主库完整 Debug/Release 已重跑，历史结果仍见 [N0](N0.md)。

正常报告记录父提交、实际二进制、主锁和实验全部源文件 hash；原始日志含本机路径，只保留在忽略目录，不原样公开。

| 本地证据 | SHA-256 |
| --- | --- |
| `target/interop/n0-hysteria2/result.json` | `264a2e1b5fe60e53135a6704127afaa3794b9716393e42b84d63b0da86d7a338` |
| `target/interop/n0-hysteria2/last-failure.json` | `902df3bed772287cbcdf68ba527dce051858aedb2773b110d185ee59bf82e4e8` |
| `target/interop/n0-hysteria2-tests.log` | `3091c4c4378d74c0c8158dc7d7d036f5f3b54f9221ffad09275a532171c45ef6` |
| `target/interop/n0-hysteria2-clippy.log` | `f2568596362d32d21c76d5bd56520c7b4548f671513c77f81dcbfb20fcd56bc5` |
| `target/interop/n0-hysteria2-ios-check.log` | `8ab5a77ae298673eaf7542c3080ef91d73fb211e9761f9be3a92ea018b46224c` |
| `target/interop/n0-hysteria2-android-check.log` | `cd5522da6fc7932759be4f11e6573155b5216231c6e58bfee29e7b792c43e8b9` |
| `target/interop/n0-hysteria2-half-close.log`（诊断 FAIL） | `fe9bd6354154ebc1fb506258dba854ba900a83bc3389424e0bd4464751147d46` |

清理：仅结束当日子进程、移除自有临时证书/配置、释放端口预留。保留下载缓存、锁文件和证据；当日未改宿主网络、未创建 VM、未修改 rustls 仓库。此页通过的仅是当日子工作包；当前状态见 [N0](N0.md)，后续跳端口/Xray H3 验证不抵扣本页原生半关闭失败或其他门禁。

# XHTTP：对齐 Mihomo 的整连接关闭

日期：2026-09-23。**本次关闭修复通过；N0 整体仍未签收。** 依据追加确认，XHTTP 客户端以 Mihomo 的关闭行为为目标，不再要求上传 EOF 后继续读取尾包。修复覆盖既有生产 H2 三种模式及独立 H3 实验；不是生产 H3、完整 XHTTP 或下一版协议的签收。

## 契约与实现

Mihomo 的 relay 在上传 EOF 后尝试 `CloseWrite`，不具备该接口时调用 `Close`。XHTTP `Conn` 没有 `CloseWrite`；它依次关闭 writer、reader 并调用 onClose。packet-up 的待完成上传最多等待1秒，然后取消。依据：[relay](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/common/net/sing.go)、[XHTTP Conn](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/transport/xhttp/conn.go)、[上传与取消](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/transport/xhttp/client.go)。这与“用 Mihomo 作服务端、任意客户端保留下行”的半关闭测试不是同一命题。

- 生产 `XHttpClient::connect` / `connect_with_download` 返回的流在 `shutdown()` 时结束整条逻辑连接。stream-one、stream-up、packet-up 以及后两者的独立下载腿共用私有关闭包装，不更改其他协议、通用 relay 或 socket/protect seam。
- 先尝试结束/完成上传；pending packet-up POST 最多等待1秒。即使上传返回错误，也释放下行、缓冲和连接 driver 的所有权；驱动沿用已有取消机制。阻塞 reader 被唤醒，关闭后读写返回 `BrokenPipe`，重复 shutdown 成功。不依赖调用方随后 Drop 整个流才释放下载连接。
- 这是逻辑连接关闭，不承诺关闭时未完成上传或未读取下行继续交付。需要完整响应的应用必须在关闭前读完；只在发送 EOF 后才生成响应的应用不获得 XHTTP 半关闭保证。正常传输的数据完整性仍单独校验，不能用新关闭契约掩盖传输损坏。
- H3 仍在独立 N0 workspace：验证完整回显后结束 request、取消 response，并释放 request owner；随后原有 endpoint/driver/owner 清理门槛继续执行。没有把实验接入生产配置，没有修改 Hysteria2 关闭行为。
- 没有新增依赖、生产字段或修改第三方；Invoke v5 / schema 14 不变。未来 N5 的连接复用须保留其他逻辑连接，不能从本次独占 H2/H3 实例直接推导池化场景已通过。

## 先失败，再实现

1. 在生产公开流接口补 `stream_one_shutdown_closes_both_directions_without_dropping_the_stream`。旧实现只发上传 END_STREAM，分离 reader 一直等待；测试实际以 `XHTTP shutdown left a blocked downstream reader` 失败。加入局部关闭包装后通过。
2. 扩展三种模式、共享/独立下载、已缓冲下行、响应头尚未到达、pending POST 的1秒关闭预算。既有正常数据用例调整为在关闭前读完明确长度/完整响应，不再隐含要求半关闭。
3. 新增 H3 `xray-h3-close`，先对旧实验执行：旧代码忽略关闭请求，目标已收到65,536 bytes，客户端仍等下行，得到 `deadline`。记录 `20260923T034751Z-6de708a5` 保留 FAIL。实现 request/response 一起终止后，新运行通过。
4. 加入官方 Mihomo **客户端**作为对照，使用同一 Xray、相同 VLESS/XHTTP H3 stream-one 与两类 origin：正常响应、等待 EOF 才尝试写尾包。Mihomo 经本机 SOCKS5 接收应用 EOF；VCore N0 probe 显式触发对应的关闭动作。两者都完整收到关闭前的服务器先发及64KiB回显，关闭用例的 origin 均结束；Mihomo 应用端在5秒内收到 EOF/RST且没有尾包，VCore 取消响应且清理完成。

对照客户端显式信任临时测试证书，未开启 skip-cert-verify。VCore 原有错误证书名称、错误路径、错误身份和三处 protect 负例保留。

## 本次验证

全部命令从 VCore 根目录执行；未运行的外部/设备用例不由普通 Cargo 结果抵扣。

| 检查 | 结果 |
| --- | --- |
| `cargo test --locked --all-features --lib transport::xhttp::tests` | 18/18 PASS；三模式及独立下载；保持流句柄时对端在2秒内关闭 |
| `cargo test --locked --all-features --all-targets` | PASS：572 lib + 4 代理组兼容 + 2 fixture；真实 GeoData 与外部进程项目仍 ignored |
| `cargo test --locked --release --all-features --all-targets` | PASS：同上，不用 Debug 代替 Release |
| `cargo clippy --locked --all-features --lib --bins -- -D warnings` | PASS，不是 all-targets clippy |
| `cargo check --locked --no-default-features --lib` | PASS，保留既有精简 feature warnings |
| `cargo test --locked --manifest-path crates/vcore-netstack/Cargo.toml --all-targets` | PASS：8 unit + 9 integration；未改通用 TCP 半关闭 |
| `uv run --project scripts --locked vcore-scripts check mihomo-interop --container --extended` | PASS：旧协议/组/链/模拟 TUN、100次生命周期与100次32-flow重建；外部 Rust 测试43.22秒 |
| 独立 spike test / all-targets clippy `-D warnings` | 6/6 PASS / PASS；路径依赖精简 VCore 的既有97条 warnings 未掩盖 |
| 独立 spike iOS / Android arm64 `cargo check --all-targets` | PASS，只有交叉检查；Android NDK28.2.13676358 / API24 |
| `native_h3.py --compare-mihomo-close` | 11/11 PASS：8项原有场景 + VCore关闭 + Mihomo正常响应/关闭对照 |
| `run.py --native-hysteria` | 8/8 PASS；共用 origin 增加完成通知，HY2 行为不变 |
| Python 离线测试、C header / TLS 依赖审计 | 42/42 PASS；两项审计 PASS，既有 SS 局部 AWS-LC 例外未扩大 |
| 主工程/独立工程 fmt、scripts与三个harness的ruff检查 | PASS；`git diff --check` PASS |

Debug/Release lib test 各保留10条既有 unused-import warnings。没有因本次修复顺手清理无关源码。独立实验复现：

```sh
cargo build --locked --manifest-path tests/protocols/spikes/hysteria2/Cargo.toml \
  --target-dir target/interop/n0-hysteria2-build
uv run --project scripts --locked python tests/protocols/spikes/hysteria2/native_h3.py --compare-mihomo-close
uv run --project scripts --locked python tests/protocols/spikes/hysteria2/run.py --native-hysteria
```

其余独立编译命令及平台说明沿用[实验 README](../../../tests/protocols/spikes/hysteria2/README.md)和[编译记录](N0-hysteria2.md#验证命令与证据)。各检查日志位于 `target/interop/runs/xhttp-close-20260923/`。

Mihomo 扩展回归的快速重建耗时24,940 ms；FD为6 → 195 → 6；在用堆基线52,336 B、首轮活动4,747,920 B、末轮活动5,387,504 B、Stop后64,176 B。活动堆仍有增长，完整曲线保留；本次没有1800秒长测，不宣称 N9 堆趋势或无泄漏门槛通过。

## 输入身份与可追溯证据

- 分支 `feat/next-protocols`，被测输入为父提交 `983abff8d2744473c242e2db5db5b9ada84bdda0` 加本次源码/测试修改。提交发生在验证后，不冒称当时已存在后续提交。
- 宿主 macOS27.0（26A428）ARM64，Rust/Cargo1.98.1、uv0.12.18；容器沿用既有专用 host-only 环境。交叉检查不是设备运行。
- 本次四个变更源码/脚本文件的 `git diff` SHA-256 为 `3530516c75f3f98d3ebd83c795aa6589dce85d5316097ecf3e6fd51b13ef25a0`：生产 `src/transport/xhttp.rs`，独立实验 `src/xhttp.rs`、`native_h3.py`、`run.py`。不包含证据文档自身。生产文件 SHA-256 为 `01f30b867b717cf1de209bd7f6897c7e4d05859acda73c8a12983b3d2f921ad8`。
- 主锁 SHA-256 `64866bfff397559e3b5e9cb03094cfb229ccaf28ae2c8fae0a549d3a9106f8e2`；独立锁 `26114362039efecee8d9253a0aab6f2074e82b4e1f177d85d4ca3f6326aaba58`，均未更改。rustls仍为原 `df261c84cbac4f708e63ac8644ce70daa90d771c`、TLS ring / 官方 tokio-rustls。
- 官方 Mihomo latest 实测 v1.19.31，Go1.26.8；Darwin程序摘要 `fae1f37e28ee53fcf5be7a8bb121099db1fe442e44205734ed49c62579364090`，Linux程序摘要 `1b315bc038d05f84ee86d232f3c3d2b020b5044e9b971bb8fe215b6e6a2148f3`。归档摘要见扩展回归日志；本轮与 [N0表](N0.md)一致。
- 官方 Xray latest 实测26.3.27 / d2758a0 / Go1.26.1；ZIP摘要 `2e93a67e8aa1936ecefb307e120830fcbd4c643ab9b1c46a2d0838d5f8409eaf`，程序摘要 `5d9dd24c0aba4b6cfcc6a33a5d67f854816ee17f392bf932ec8176da46f7e404`。
- 对端每次重新从官方 latest 下载并查询版本；不查API、不本地编译、不回退旧缓存。摘要只标识内容，不冒称官方签名验证。H3报告含完整实验输入与二进制摘要。

| 原始证据（相对 `target/interop/`） | SHA-256 |
| --- | --- |
| `n0-xray-h3/20260923T034751Z-6de708a5/result.json`，关闭用例 RED | `17ca1d06c20e021a3c5744284a43614bc1d46f1a9b5c86e2bb9f5168ffe444a1` |
| `n0-xray-h3/20260923T035524Z-90076747/result.json`，最终11项 GREEN | `1d14c5f48f9ed8e97f8c877733b2a72ff9546f432b00c65d0af739e603551e69` |
| `n0-xray-h3/20260923T035838Z-8660edc0/result.json`，raw半关闭仍 FAIL | `19bf9a2bcf7be99661b74892e67435fa17c42b0a98e901a853729c822a0c5807` |
| `n0-hysteria2/result.json`，8项共用夹具回归 | `0989520521453545744bf2e16fc9ec4547ce5d6eecc846cfffab42cb841e30f4` |
| `runs/xhttp-close-20260923/debug.log` | `9562cff2e638f9c781db136a2067d6ef3319d77931e0f3650baadd20a85edec7` |
| `runs/xhttp-close-20260923/release.log` | `ef05ee67015ee00f0fae91a044f4ee4af7b7c8d4f21054ab2e99b33b9db32997` |
| `runs/xhttp-close-20260923/mihomo-extended.log` | `0d3cee40be1ef04847ba4cf87478c9ff049de76834435a280093770ceac049a7` |

## 保留失败与未执行项

原 Xray raw request-EOF/尾包诊断仍独立保留，`native_h3.py --half-close` 仍要求保留下行，失败时非零退出。它测的是旧半关闭能力，不是这次确认的 Mihomo 整连接关闭契约；不能改写历史失败为 PASS。原生 Hysteria 半关闭失败也未修复或豁免，仍见[历史记录](N0-hysteria2.md)。

本次额外复跑上述诊断：正常9项通过，第10项得到 `xhttp_data_mismatch`，实收65,552 / 预期65,566 bytes，目标收到65,536 bytes，仍缺14-byte尾部；清理通过，命令退出1。该 FAIL 与11项新契约通过报告分开保存，不通过删除尾部断言或修改第三方制造成功。

未签收生产 H3、其他 HTTP版本/下载拓扑/复用、完整N5、N0其余门禁、1800秒长测、物理设备、Windows、远端CI或正式包。自建进程/容器与临时配置已清理，保留既有专用网络、镜像及本地证据；没有修改宿主VPN/路由/DNS/防火墙、第三方源码或其他仓库，没有 push。

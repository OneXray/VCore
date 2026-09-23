# N0-B：流传输候选依赖与公开接口

调研日期：2026-09-23。本文是 **TLS / 普通 WebSocket / gRPC 流适配器的依赖研究**，不是生产支持声明，也不把源码可用性写成平台或互通 PASS。实际实验、命令与平台结果由对应验收记录单列，阶段总状态见 [N0](N0.md)。

## 候选结论与版本边界

复用现有 TLS 和 HTTP/2，新增 WS 候选只进入独立实验 workspace。三者均接受已经建立的 `AsyncRead + AsyncWrite + Unpin`，不需要代替 `Dialer` 建立 socket；VCore 继续拥有上游选择、平台保护、连接期限与任务回收。

| 层 | 本轮候选 / 最小 feature | 许可证元数据 | 依据 |
| --- | --- | --- | --- |
| TLS | 既有 `tokio-rustls =0.26.4`，`default-features=false`，`ring,tls12` | MIT OR Apache-2.0 | [官方发布源码 Cargo.toml](https://github.com/rustls/tokio-rustls/blob/0c14e1496ef50adade4ac7c7d1f0270dfb3cdda5/Cargo.toml) |
| TLS provider | 既有 `rustls =0.23.43`，自有 fork revision `df261c84cbac4f708e63ac8644ce70daa90d771c`，`default-features=false`，`ring,std,tls12` | Apache-2.0 OR ISC OR MIT | [锁定 fork 的 Cargo.toml](https://github.com/OneVCore/rustls/blob/df261c84cbac4f708e63ac8644ce70daa90d771c/rustls/Cargo.toml) |
| TLS crypto | 既有 `ring 0.17.14`，经上述 feature 选用 | Apache-2.0 AND ISC；分文件通知见发行包 | [crate 元数据及许可文件](https://docs.rs/crate/ring/0.17.14/source/) |
| WebSocket | `tokio-tungstenite =0.29.0`，`default-features=false`，仅 `handshake`；传递 `tungstenite 0.29.0/handshake` | tokio-tungstenite：MIT；tungstenite：MIT OR Apache-2.0 | [binding manifest](https://github.com/snapview/tokio-tungstenite/blob/v0.29.0/Cargo.toml)、[protocol manifest](https://github.com/snapview/tungstenite-rs/blob/v0.29.0/Cargo.toml) |
| HTTP/2 / gRPC | 既有 `h2 =0.4.15`，不启用 `unstable`；复用 `http 1`、`bytes 1` | MIT | [h2 manifest](https://github.com/hyperium/h2/blob/v0.4.15/Cargo.toml) |

这里只记录发布包声明，不代替最终链接图的许可证审计。`ring` 的多份原始通知不能被一个简化 SPDX 字符串替代；未来发布仍按实际链接依赖保存所需许可信息。

实际查询官方 sparse registry 时，最新非撤回版本为 tokio-tungstenite **0.30.0**、h2 **0.4.19**、tokio-rustls **0.26.5**；上表不是“最新版”声明。保留已有 h2/TLS 锁，WS 0.29.0 则与本次参考的 Clash-RS 一致，避免可行性研究附带生产升级。WS 0.30 的记录包含服务端 Key 校验、rand/sha 更新和 MSRV 1.85，后续依赖升级需独立验收。[WS registry](https://index.crates.io/to/ki/tokio-tungstenite)、[h2 registry](https://index.crates.io/2/h2)、[TLS binding registry](https://index.crates.io/to/ki/tokio-rustls)、[tungstenite 0.30 changelog](https://github.com/snapview/tungstenite-rs/blob/v0.30.0/CHANGELOG.md)。

版本风险不能省略：h2 0.4.16–0.4.19 已追加小 DATA 帧限制、RecvStream drop 容量释放、`poll_trailers` 唤醒、EOS 后 RST 数据处理、`write(0)` busy-loop 与 HPACK 表上限等修复。本轮沿用 0.4.15 证明接口可行，**不代表已有这些修复或完成生产版本最终审定**；N1 接入前须单独评估较新 patch 的升级与回归，不修改第三方源码绕过问题。[官方 h2 changelog](https://github.com/hyperium/h2/blob/v0.4.19/CHANGELOG.md)。

Clash-RS 参考 checkout 为 `470bc5a427bfaea3fafcedf32563010f9a47b691`：WS 使用 `client_async_with_config` 包装 `AnyStream`，gRPC 直接使用 h2，不依赖 tonic 来处理这条数据路径。借鉴的是流适配边界，不复制其 TLS fork、依赖集合或后台任务所有权方案。[Clash-RS WS](https://github.com/Watfaq/clash-rs/blob/470bc5a427bfaea3fafcedf32563010f9a47b691/clash-lib/src/proxy/transport/ws/mod.rs)、[gRPC](https://github.com/Watfaq/clash-rs/blob/470bc5a427bfaea3fafcedf32563010f9a47b691/clash-lib/src/proxy/transport/grpc.rs)、[workspace patches](https://github.com/Watfaq/clash-rs/blob/470bc5a427bfaea3fafcedf32563010f9a47b691/Cargo.toml)。

## 可注入流与资源约束

### TLS

- 官方 `TlsConnector::connect/connect_with` 接收调用方的 IO；握手 Future 持有该 IO，不需要 DNS 或 socket factory。`connect_with` 可调用公开的 `set_buffer_limit(Some(n))`。该限制约束待发送明文和 TLS record 缓冲，**不是整个握手、证书链或连接总内存的通用硬上限**。[connector](https://github.com/rustls/tokio-rustls/blob/0c14e1496ef50adade4ac7c7d1f0270dfb3cdda5/src/client.rs)、[rustls buffer contract](https://github.com/OneVCore/rustls/blob/df261c84cbac4f708e63ac8644ce70daa90d771c/rustls/src/conn.rs)。
- TLS 默认 feature 会引入 AWS-LC；tokio-rustls 默认还启用 logging。因此继续显式关闭 defaults，仅使用既有 ring provider；本工作不扩大 SS 的局部 AWS-LC 例外，也不引入 Watfaq TLS fork、native-tls、系统根证书扫描或第二套 rustls。[上述 manifests](https://github.com/rustls/tokio-rustls/blob/0c14e1496ef50adade4ac7c7d1f0270dfb3cdda5/Cargo.toml)。
- 取消握手时必须销毁持有 IO 的 Future；成功后由会话持有流。`TlsStream::poll_shutdown` 会发 `close_notify`，随后调用底层 `poll_shutdown`；它不等同于 Mihomo 的仅 TLS 写关闭，见下节。读写失败和取消后的连接释放需实际实验确认。[TLS shutdown 源码](https://github.com/rustls/tokio-rustls/blob/0c14e1496ef50adade4ac7c7d1f0270dfb3cdda5/src/client.rs)。

### WebSocket

- 使用 `client_async_with_config(request, injected_stream, Some(config))`；TLS 在调用前由既有适配器完成。关闭 `connect`、`stream`、所有 `native-tls` / `rustls-tls-*` features，避免 URL 拨号器与附带 TLS 栈。[公开握手 API](https://github.com/snapview/tokio-tungstenite/blob/v0.29.0/src/lib.rs)、[feature graph](https://github.com/snapview/tokio-tungstenite/blob/v0.29.0/Cargo.toml)。
- 显式设置 `read_buffer_size`、`write_buffer_size`、`max_write_buffer_size`、`max_message_size`、`max_frame_size`。默认读写缓冲各 128 KiB，写缓冲上限无限，消息 64 MiB、帧 16 MiB；不直接作为客户端预算。`max_write_buffer_size` 必须大于写缓冲，并容纳至少一个受控发送块及帧开销；还需限制调用方单次发送块，不能只限制入站帧。[WebSocketConfig](https://github.com/snapview/tungstenite-rs/blob/v0.29.0/src/protocol/mod.rs)。
- `poll_ready → start_send` 接受后只记账一次；如果后续 flush Pending，不重发相同输入。内置 Ping/Pong/Close 处理仍需驱动读写/flush。关闭帧写出、底层写关闭、释放整个会话是不同动作，不能直接把 `Sink::poll_close` 当作统一代理 EOF。[Sink 实现](https://github.com/snapview/tokio-tungstenite/blob/v0.29.0/src/lib.rs)。
- HTTP upgrade 另有内置头部攻击限制（64 KiB 总读取、读取次数等），不是 WebSocketConfig 的消息限制；握手还需统一超时。恶意超大/分片消息、写阻塞和取消必须单独测试。[handshake machine](https://github.com/snapview/tungstenite-rs/blob/v0.29.0/src/handshake/machine.rs)。
- 上游会在 trace 输出完整升级请求、消息和帧；可能包含敏感头或 early-data。实验应显式编译禁用 `log`，未来生产接入也不能仅依赖 SS feature 才禁用日志。[request trace](https://github.com/snapview/tungstenite-rs/blob/v0.29.0/src/handshake/client.rs)、[frame trace](https://github.com/snapview/tungstenite-rs/blob/v0.29.0/src/protocol/mod.rs)。

### HTTP/2 / gRPC

- `h2::client::Builder::handshake(io)` 返回 `SendRequest` 和独立 `Connection` Future，IO 边界符合现有流注入。gRPC 的五字节记录头与 protobuf 字节字段可在 VCore 自有、有界 codec 中处理，无需引入 hyper/tonic、其客户端拨号器或额外 TLS。[Builder](https://github.com/hyperium/h2/blob/v0.4.15/src/client.rs)、[gRPC HTTP/2 格式](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md)。
- 明确窗口、帧/头部大小和 stream 数；禁用 push。`max_send_buffer_size` 影响容量通知，**不是 `send_data` 的硬性总缓冲上限**。发送须按 `reserve_capacity/poll_capacity` 实际所得字节分块，不在拿到部分额度后继续提交整帧；取消未消费预留。[SendStream flow-control](https://github.com/hyperium/h2/blob/v0.4.15/src/share.rs)、[builder limit](https://github.com/hyperium/h2/blob/v0.4.15/src/client.rs)。
- 接收 DATA 仅在消费/受控保留后 `release_capacity`；gRPC/protobuf 声明长度、跨 DATA 拼接残留与单条 payload 各有独立上限。HTTP/2 帧长不是 gRPC 消息长的上限，HTTP 200 也不能代替 gRPC 编解码与尾部状态校验。[FlowControl](https://github.com/hyperium/h2/blob/v0.4.15/src/share.rs)、[gRPC framing/trailers](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md)。
- `send_data(..., true)` / trailers 是发送方向 EOS，`send_reset` 取消请求响应两方向。`Connection` 驱动任务必须由会话所有者持有并能 cancel/join；仅丢弃一个 `SendRequest` 或 detach 一个 spawn 不证明底层流已释放。共享 H2 的单个 stream 关闭也不应误称为物理连接关闭。[h2 stream contract](https://github.com/hyperium/h2/blob/v0.4.15/src/share.rs)。

## Mihomo EOF 对照：必须沿包装链判断

参考 Mihomo checkout `ab405bad5beeeac8b003bb01f60f134f6df54471`。以下为源码推导的测试预期，**不是差分运行结果**。`Relay` 仅在拷贝正常 EOF 时执行 `closeWrite`；遇错误执行完整 Close。`common.Cast` 先查 `CloseWrite`，再递归 `Upstream()` / `NetConn()`，不能只看最外层是否声明 CloseWrite。[Relay](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/common/net/sing.go)、[sing v0.5.7 Cast](https://github.com/MetaCubeX/sing/blob/v0.5.7/common/upstream.go)。

| 普通连接路径 | 正常上传 EOF 的源码预期 |
| --- | --- |
| VLESS → TLS | VLESS/Extended 包装解包至 TLS `CloseWrite`：发送 `close_notify`，保留读方向，不调用底层 TCP CloseWrite |
| VLESS → 普通 WS → TLS | WS、Buffered、Deadline 包装均可继续解包至 TLS；行为同上，不因 WS 没有 CloseWrite 就调用 WS Close |
| VLESS → 普通 WS → TCP | 解包到 TCP CloseWrite；不要求发 WS Close frame，读方向仍存在 |
| VLESS → gRPC/gun | 客户端 gun.Conn 无 CloseWrite、Upstream 或 NetConn，最终完整关闭该逻辑 stream 的 writer/reader；池内物理 H2 连接可以继续存在 |

依据：[VLESS wrapper](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/transport/vless/conn.go)、[WS/early-data wrapper](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/transport/vmess/websocket.go)、[Buffered wrapper](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/common/net/bufconn.go)、[TLS 0.1.8 CloseWrite](https://github.com/MetaCubeX/tls/blob/v0.1.8/conn.go)、[gun client](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/transport/gun/gun.go)。

因此普通 TLS/WS 的 Rust 适配器不能直接照搬 XHTTP 的整逻辑连接关闭契约。若以公开 rustls API 发 `close_notify` 并 flush，仍需自身记录写关闭状态，禁止后续业务写；tungstenite 在没有 WS Close frame 时可能报告 `ResetWithoutClosingHandshake`，应区分已验证的底层正常 EOF 与真实截断/协议错误。[tungstenite EOF 分支](https://github.com/snapview/tungstenite-rs/blob/v0.29.0/src/protocol/mod.rs)。

WS early-data 包装的 `Upstream()` 返回握手前 underlay，可能与普通 WSS 的 TLS 解包路径不同；本轮不能从普通 WS 推广其 EOF 行为。其余安全层、early-data、连接池与复用拓扑也应在各自组合阶段验证。

## 平台、依赖与验收边界

| 平台 | 由源码/依赖能确定的边界 | 尚需执行的证据 |
| --- | --- | --- |
| Apple | 注入流 API 不依赖 NetworkExtension 或自行建 socket；仍使用既有 ring C/汇编与 Apple ABI 路径 | macOS 宿主实验、目标 iOS 编译；真实设备及宿主隧道另验 |
| Android | 协议包装层不替代 `Dialer` protect；不引入 OpenSSL/native-tls；ring 已有 Android target 分支 | NDK 目标编译、protect 拒绝与取消；真机流量另验 |
| Windows | WS/h2/TLS 协议 IO 不依赖 Unix fd；ring Windows ARM64 构建明确选择 clang 路径 | 对应 MSVC/clang 工具链编译与链接、包内运行；macOS 交叉源码检查不能代替 Windows 运行 |

这些是接口与构建源码的观察，不是上游对 VCore 场景的兼容保证。[ring 0.17.14 build.rs](https://docs.rs/crate/ring/0.17.14/source/build.rs)、[tokio-rustls IO trait](https://github.com/rustls/tokio-rustls/blob/0c14e1496ef50adade4ac7c7d1f0270dfb3cdda5/src/client.rs)、[WS IO trait](https://github.com/snapview/tokio-tungstenite/blob/v0.29.0/src/lib.rs)、[h2 IO trait](https://github.com/hyperium/h2/blob/v0.4.15/src/client.rs)。Linux 不是因这些可移植依赖而新增的产品支持平台。

独立实验签收至少分开记录：

1. 锁定图的唯一 rustls、官方 tokio-rustls、ring 与禁用日志；没有新增 TLS AWS-LC/native-tls/Watfaq fork，生产 Cargo 文件保持原样。
2. 已注入流上的握手、分片、背压、失败、取消与显式 Stop/join；用公共边界证明资源释放，不依靠内部指针或手工布尔标志宣称已回收。
3. 官方 Mihomo 客户端与 VCore 实验面对同一 fixture 的 EOF 差分；真实 listener 互通与源码推导分列，不用一方充当另一方。
4. 实际目标编译、宿主运行、真机和打包结果各自标注；未执行项保持 NOT RUN。普通流接口通过不抵扣 Vision、QUIC、ECH、WS early-data 或完整 gRPC/XHTTP 组合门禁。

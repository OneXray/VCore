# Windows Session Runtime 重构计划

> 状态：Phase 0 已于 2026-08-23 在 Windows 11 ARM64 build 26200.9168 通过；架构已按实测结果收敛，进入正式实现。
>
> 范围：Windows TUN runtime；不改变 Apple/Android、Invoke API v5、配置 schema revision 11 或既有代理协议。
>
> 基线：Windows 11 ARM64 开发身份已经完成 Phase 3A。Windows 10、原生 x64、物理 IPv6、WACK、正式 identity 与 Store submission 继续延期到最终发布阶段。

## 1. 问题

VCore 已经具备本次需要的业务能力：

- `TunTrafficStats` 和 authenticated `GET /traffic` Controller；
- SOCKS5 outbound 的 CONNECT、RFC 1929 authentication 和 UDP ASSOCIATE；
- VLESS/XHTTP/TLS/REALITY、AnyTLS、DIRECT、DNS、rules、GeoData 和任意无环代理链。

当前 Windows 障碍来自进程边界，而不是协议缺失：

1. `Windows VPN provider` 位于 AppContainer，并在同一进程内持有完整 VCore runtime。
2. Controller 因而监听在 AppContainer loopback。Windows 11 ARM64 build 26200.9168 的独立最小 MSIX 对照中，medium-integrity full-trust client 连接该 listener 一直停在 `SYN_SENT` 后超时；`LoopbackAccessRules` 没有改变结果。
3. 同理，provider 内的 VCore 无法把普通 `127.0.0.1:1080` full-trust SOCKS5 service 当作可靠产品路径。
4. VCore 本身已经支持等价的严格 YAML SOCKS5 mapping；`socks5://127.0.0.1:1080` 只是 endpoint 描述，不引入第二套 URI 配置语法。

本次重构把完整 Windows VCore runtime 移到 package 内的 full-trust Session Host。AppContainer provider 只保留 `Windows.Networking.Vpn` 生命周期、packet buffer 所有权、route/DNS 安装、物理网络选择和 fail-closed 责任。

## 2. 目标

- Windows TUN traffic snapshot 能由 Flutter 通过现有 loopback Controller 查询。
- VCore 能把现有 SOCKS5 outbound 配置指向 full-trust loopback service，例如：

  ```yaml
  proxies:
    - name: local-socks
      type: socks5
      server: 127.0.0.1
      port: 1080
      udp: true
  ```

- VCore 仍是完整、独立的代理 core；tun-to-SOCKS5 只是一种配置方式。
- 保留 VLESS、SOCKS5、AnyTLS、DIRECT、DNS、rules、GeoData、sniffer、Controller 和 proxy-chain 行为。
- 保留 Flutter 退出后 VPN 继续运行、App 重启恢复状态、网络变化 fail-closed 和同步 Stop barrier。
- 只使用 `windows-rs` / `Windows.Networking.Vpn`；不使用 Wintun、`CheckNetIsolation` exemption 或产品级 `LoopbackAccessRules`。
- 最终 Windows 只保留一条 packet path，不保留 provider 内嵌 runtime fallback。

## 3. 非目标

- 不集成、启动、配置或监管 Xray-core、mihomo 或其他 external core。
- 不让 VCore管理 `127.0.0.1:1080` server 的生命周期。
- 不替外部 SOCKS5 server 保护 outer sockets；该 server 必须自行绕过 VPN 或绑定物理出口。
- 不增加 SOCKS5 inbound、URI 配置 parser、per-node traffic metrics、持续 metrics stream 或新的 Invoke method。
- 不改变当前 YAML、snapshot token、Flutter start/status/stop API 或 session record shape。
- 不在第一版实现 shared-memory ring、packet batching、compression、heartbeat、自动网络迁移或从 Windows 设置独立启动 Session Host。
- 不把延期的 Phase 3B 发布矩阵算作本次开发验收已完成。

## 4. 目标架构

```text
Flutter foreground (full trust)
  ├─ VCoreInvoke                         # 业务 API，保持 v5
  └─ VCoreWindowsVpnInvoke               # host bridge，保持 revision 1
         │ starts
         ▼
vcore-windows-session-host.exe (full trust, one process per VPN session)
  ├─ immutable snapshot validation
  ├─ PreparedCore / RunningCore
  ├─ WindowsIpcTunIo
  ├─ VLESS / SOCKS5 / AnyTLS / DIRECT
  ├─ DNS / rules / GeoData / sniffer
  └─ authenticated TrafficController
         ▲
         │ same-package Windows packet channel
         │ Provider pipe server + Session Host client
         │ control pipe + full-duplex data pipe
         ▼
vcore-windows-vpn-host.exe (AppContainer)
  └─ vcore.dll / OneVCore.VpnBackgroundTask
       ├─ VpnChannel lifecycle
       ├─ VpnPacketBuffer ownership
       ├─ bounded callback queues
       ├─ loopback DatagramSocket Decapsulate wake
       ├─ physical network selection/monitor
       └─ fail-closed VpnChannel.Stop
```

### 4.1 所有权

| 参与者 | 拥有 | 不拥有 |
| --- | --- | --- |
| Flutter | 用户命令、session record、Controller metadata、状态展示 | VCore TUN runtime、packet channel、Provider state |
| Windows host bridge | snapshot publication、profile management、Session Host process launch | packet data、runtime task、代理 flow |
| Windows Session Host | 一次 VCore TUN runtime、Controller、GeoData registration、packet-channel client | `VpnChannel`、Windows routes、外部 SOCKS5 service |
| Windows VPN provider | `VpnChannel`、AppContainer-local pipe server、WinRT buffers、callback queues、physical network identity、network monitor | YAML 业务解析、proxy graph、Controller、GeoData |
| 外部 SOCKS5 server | 自身 listener、outer sockets 和绕过 VPN 的方式 | VCore session、Windows VPN profile |

Session Host 是每次 VPN session 一个新进程。它不复用 runtime、不承接下一次 Connect，也不是常驻 daemon。

## 5. 保持不变的公共契约

| 边界 | 结果 |
| --- | --- |
| Invoke API | v5，不新增 method |
| 配置 schema | revision 11，严格 Mihomo-shaped YAML 不变 |
| SOCKS5 配置 | 继续使用 `type/server/port/username/password/udp` mapping；不接受 URI shorthand |
| Windows host bridge | revision 1，现有六个 method 和 JSON shape 不变 |
| Start | `startVpn({configYaml})` 不变 |
| Snapshot | `onevcore-v1:<64 lowercase sha256>` 和 `.yaml` 内容地址不变 |
| Windows profile | 一个 package-owned `OneVCore` profile |
| Session record | 不新增 PID、pipe name、physical binding 或 runtime handle |
| Traffic API | authenticated `GET /traffic` 四字段 snapshot 不变 |
| Apple/Android | TUN fd、protect 和 runtime 行为不变 |

新的 packet-channel protocol 是 package 内部 version 1，不属于 C ABI、Invoke API 或 YAML schema。

## 6. Session 启动协议

启动顺序固定如下：

1. Flutter 调用 `VCoreWindowsVpnInvoke.startVpn(configYaml)`。
2. host bridge 使用当前 VCore parser 验证 TUN config，并发布 immutable snapshot。
3. 若 profile 已 Connected 且 token 相同，按现有语义幂等返回，不启动第二个 Session Host。
4. 对 disconnected profile，host bridge 使用 `IApplicationActivationManager::ActivateApplication` 激活 manifest 中隐藏的 `SessionHost` Application，不经过 shell、不搜索 `PATH`，并只传递：

   ```text
   --snapshot-token onevcore-v1:<sha256>
   ```

5. activation 返回精确 PID；host bridge 立即打开并暂时持有该 process handle。Session Host 获取 package identity/LocalState 后等待 Provider rendezvous。
6. host bridge 更新单一 VPN profile，然后调用 `ConnectProfileAsync`。
7. Windows 激活 Provider。Provider 在安装 VPN routes 前选择 `Physical network binding`，并在自己的 AppContainer namespace 创建 first-instance control/data pipe servers。
8. Provider 通过 `GetAppContainerNamedObjectPath` 取得当前相对 object path，原子发布最多 4 KiB 的严格内部 rendezvous record：protocol version、snapshot token、object path 和两个固定 pipe leaf name；它不含 YAML、secret、PID 或 physical binding。
9. Session Host 读取并校验 rendezvous token，使用当前 Windows session ID 把相对 object path 限定为 `\\.\pipe\Sessions\<id>\AppContainerNamedObjects\<sid>\...`，再作为 full-trust client 连接两条 pipe。
10. Session Host 发送 `SessionHello`；Provider 返回 internal protocol version、profile token 和 immutable physical binding。
11. Session Host 严格比较 command-line token、rendezvous token、handshake token 和 snapshot digest，读取 YAML并启动 VCore。
12. Controller、GeoData、proxy graph 和 `WindowsIpcTunIo` 全部成功后，Session Host 返回 `RuntimeReady`。
13. Provider 才调用 `StartWithMainTransport`，安装 network callback 并 arm fail-closed worker。
14. `ConnectProfileAsync` 成功后，Flutter 按现有事务写入 `run/start.json`；internal rendezvous 随后删除。

任一步失败都必须：

- 返回 bounded、redacted error；
- 关闭 packet channel；
- 停止当前启动创建的 Session Host；
- 让 profile 收敛为 Disconnected；
- 不回退到 provider 内嵌 VCore runtime。

Windows 设置直接 Connect 时若没有匹配 Session Host，Provider 立即使 Connect 失败。第一版不由 AppContainer Provider 启动 full-trust process。

## 7. Windows packet channel

### 7.1 平台依据与验证边界

微软文档明确说明：

- packaged application 的 named pipe 默认用于同 package 进程；
- packaged/unpackaged app 的 pipe name 必须使用 `\\.\pipe\LOCAL\...`；
- named pipe server 可以提供自定义 security attributes。

这些文档不能代替当前 package 模型的实机结果。Phase 0 已证明 unqualified `LOCAL` name 不会自动跨越 full-trust/AppContainer namespace；产品必须由 AppContainer Provider 创建对象，再由 Session Host 使用 provider 发布的相对 object path 构造 qualified name。

### 7.2 两条 pipe

Provider 在自己的 AppContainer namespace 创建两条 server pipe：

```text
\\.\pipe\LOCAL\OneVCore.Vpn.Control.v1
\\.\pipe\LOCAL\OneVCore.Vpn.Data.v1
```

full-trust Session Host 根据 Provider rendezvous 和当前 Windows session ID 使用：

```text
\\.\pipe\Sessions\<id>\AppContainerNamedObjects\<package-sid>\OneVCore.Vpn.Control.v1
\\.\pipe\Sessions\<id>\AppContainerNamedObjects\<package-sid>\OneVCore.Vpn.Data.v1
```

- AppContainer namespace 自然隔离 Dev/Store identity，无需在 leaf name重复 PFN hash。
- control pipe 与 data pipe 分开，控制消息不受 packet backpressure 阻塞。
- Provider server 使用 first-instance 与 reject-remote-client 语义；control first instance 同时拒绝同一 Provider 内的重复 session。
- Session Host 只接受 rendezvous 给出的 canonical relative path和固定 leaf name，不接受任意 pipe path参数。

### 7.3 Namespace 与 rendezvous

Provider 使用 AppContainer默认 named-object security，不扩大 DACL，也不设置 loopback exemption。Phase 0实测中，同用户 unpackaged process 对两个 unqualified `LOCAL` name均得到 `ERROR_FILE_NOT_FOUND (2)`；只有通过同包 Provider发布的 qualified AppContainer path，隐藏的 full-trust Session Host才能连接。

`vcore/windows/rendezvous.json` 是最多 4 KiB 的原子、严格、session-scoped内部记录：

- 只由 active Provider写入；
- 包含 protocol version、snapshot token、`GetAppContainerNamedObjectPath` 返回值和固定 pipe leaf names；
- 不包含 YAML、Controller secret、physical binding、PID或业务配置；
- Session Host 校验 token/shape后读取，handshake成功即删除；
- disconnected Start在 launch前清理 stale record，active profile下不得覆盖；
- reparse point、非普通文件、超限、未知字段或 token不匹配均 fail-closed。

snapshot token不是 secret；AppContainer namespace负责访问隔离，token负责拒绝错误 session交叉连接。

### 7.4 Control framing

每条 control message：

```text
u32 big-endian JSON byte length
UTF-8 JSON bytes
```

规则：

- 最大 16 KiB；
- 每种 serde DTO 使用 `deny_unknown_fields`；
- error message 最大 4 KiB；
- 不接受重复 terminal message、顺序错误、未知 type 或尾随字段；
- 不传 YAML、Controller secret、SOCKS credentials、日志正文或任意 Invoke request。

Version 1 消息集合固定为：

```text
SessionHello { version, snapshotToken }
ProviderHello { version, snapshotToken, physicalBinding }
RuntimeReady { version }
RuntimeFailed { code, redactedMessage }
Stop
Stopped { packetCounters }
```

Timeout：

- hidden Application activation与 process handle取得：5 秒；
- rendezvous + provider handshake + VCore prepare/start：15 秒；
- orderly stop acknowledgement：10 秒；
- active packet stream 不设置 idle timeout；
- 第一版不发送 heartbeat。

### 7.5 Data framing

full-duplex data pipe 每个方向只有一个 writer。每个 frame：

```text
u16 big-endian packet length
packet bytes
```

规则：

- length 必须为 `1..=1500`；
- EOF、truncated frame、zero/oversize length 或 framing violation 终止 session；
- 合法 frame 内的无效 IP packet 仍由现有 `TunFraming::RawIp` / TunRuntime 校验并局部丢弃；
- 不增加 direction byte、checksum、compression、batch 或 shared-memory ring。

### 7.6 Callback queues

Provider 两侧容量继续为 256：

```text
Encapsulate callback
  -> copy VpnPacketBuffer bytes
  -> try_send bounded ingress
  -> packet writer task
  -> data pipe

Data pipe reader
  -> bounded egress VecDeque
  -> empty-to-nonempty DatagramSocket wake
  -> Decapsulate drains queue
```

- callback 永不等待 pipe I/O；
- queue full 时只丢当前 packet并计数；
- 所有 framework buffers 按当前 WinRT 契约归还；
- `Decapsulate` 的同进程 AppContainer loopback wake 保持不变；
- final counters 通过 `Stopped` 和 provider log 记录，不成为公共 API。

Session Host 侧 `WindowsIpcTunIo` 直接把 data pipe 映射为现有 `read_packet` / `write_packet`，继续由 `TunRuntime` 维护 traffic snapshot。

## 8. Physical network binding 与 loopback

Provider 仍是物理网络唯一 authority。它在 route 安装前选择并持有：

- adapter GUID；
- network identity；
- IPv4 source + nonzero interface index（若该 family 可用）；
- IPv6 source + nonzero interface index（若该 family 可用）。

Provider 把 immutable binding 放入 `ProviderHello`，但继续独自订阅 `NetworkStatusChanged`。2 秒静默后若 adapter、地址或 network identity 变化，Provider 调用 `VpnChannel.Stop`；Session Host 不重选网卡、不更新已有 socket、不自动重连。

Session Host 用该 binding 构造当前 `Dialer::with_windows_interface`。最终 socket seam 增加 destination-aware loopback policy：

- 解析后的 `127.0.0.0/8` 和 `::1` 不设置 physical interface option；
- loopback TCP/UDP 只绑定对应 loopback family；
- 非 loopback TCP/UDP 继续要求 source IP 与 interface index 成对存在；
- 缺少 family、`setsockopt` 或 source bind 失败时 fail-closed；
- `localhost` 名称没有特殊信任，是否 loopback 只看 resolver 返回的 IP；
- LAN/private 地址不是 loopback，不获得例外。

UDP bind 改为 destination-aware。`DirectDatagramTransport` 按 address family 与 binding class 分别复用 loopback/physical socket，避免一条 UDP association 把两种出口混用在同一 socket。

VCore 只保证到 local SOCKS5 listener/relay 的自身 socket policy。外部 SOCKS5 process 的 outer sockets 完全由该 process 负责；VCore 不增加 per-process route exclusion 或 unbound fallback。

## 9. Snapshot、Controller 与数据目录

- host bridge 继续原子发布 `LocalState/vcore/windows/snapshots/<sha256>.yaml`。
- profile 继续只保存 canonical token。
- Provider 只解析 token，不读取或解析 YAML。
- Session Host 使用现有 `SnapshotReference` 做 size、reparse-point、file type 和 digest 校验。
- snapshot prune 继续保留 current + previous，覆盖 profile activation race。
- Session Host 使用现有 `LocalState/vcore/geodata`；跨进程 GeoData lock/atomic replacement 规则不变。
- Session Host 使用现有配置中的动态 `external-controller` 和 Bearer secret。
- Controller bind 必须先于 `RuntimeReady`；bind 失败使 Connect 失败。
- Flutter 继续从 `run/start.json` 读取 Controller metadata，直接查询 full-trust loopback。
- Stop 后 Controller 关闭；每次 Session Host 重新启动，四个统计字段从零开始。

## 10. Lifecycle 与失败矩阵

| 事件 | 必须结果 |
| --- | --- |
| Flutter 窗口/进程退出 | Provider、Session Host 与 VCore继续运行 |
| Flutter 重启 | profile 是 authoritative 状态；同 token session record 恢复 Controller 查询 |
| Provider/Provider Host 退出 | Windows 清理 VPN；Session Host 从 EOF 停止 runtime并退出 |
| Session Host/VCore 异常退出 | Provider 从 EOF/RuntimeFailed 触发 fail-closed `VpnChannel.Stop` |
| physical network 改变 | Provider debounce 后 Stop；Session Host随后退出 |
| 正常 App Stop | `DisconnectProfileAsync` → Provider `Stop` → bounded host ack → `VpnChannel.Stop` |
| malformed control/data frame | 双方终止 session；Provider fail-closed |
| local SOCKS5 拒绝/认证失败 | 仅对应 flow 失败；VPN runtime 不停止 |
| Controller bind 失败 | startup 失败，profile 不进入 Connected |
| Provider 未发现 Session Host | Connect 失败；不自行启动 full-trust process |
| Session Host 5 秒内无有效 launcher/provider progression | 自行退出 |
| fixed pipe 被 stale host 占用且 profile Disconnected | Start 返回 busy；不按名称批量杀进程 |

当前 Start 持有本次新建 Session Host 的 process handle。启动失败时只能请求并在超时后终止该 handle 对应的进程；不得扫描未知 PID或按 executable name 清理。

## 11. 日志

拆分两个单 writer 文件：

```text
logs/windows-vpn-provider.log
logs/windows-vpn-provider.previous.log
logs/windows-vpn-session.log
logs/windows-vpn-session.previous.log
```

每个 current 最多 1 MiB，保留一个 previous。共享实现放入 `windows_log.rs`，但两个进程不写同一个文件。

日志不得包含：

- YAML 或完整 IPC JSON；
- Controller secret、SOCKS username/password、UUID、REALITY key/short ID；
- 目标域名/IP、DNS question、network name；
- payload。

允许记录 protocol version、session phase、address family 是否存在、packet/drop counters、error code和 bounded redacted message。

## 12. 源码变更边界

### 12.1 VCore

不做大规模 `src/windows/*` 目录迁移。只提取真实的新边界：

| 文件 | 计划 |
| --- | --- |
| `src/windows_vpn.rs` | 保留 COM activation、Provider、WinRT packet ownership、transport wake、physical network monitor、fail-closed；删除 `ProviderRuntime` 和 `run_vcore` |
| `src/windows_host.rs` | 在现有 `startVpn` 内用 `IApplicationActivationManager` 激活隐藏 Session Host，并持有精确 process handle完成 rollback；六个 bridge method不变 |
| `src/windows_snapshot.rs` | 复用 publication/verification；向 Session Host runner提供 crate 内入口 |
| `src/windows_packet_channel.rs` | 新增 AppContainer-server pipe naming、rendezvous、qualified path、control/data codec、provider/session endpoints和 strict DTO |
| `src/windows_session.rs` | 新增 Session Host 主生命周期、snapshot读取、VCore prepare/start/stop、error convergence |
| `src/windows_log.rs` | 提取 bounded per-process logger |
| `src/platform/windows_tun_io.rs` | 从同进程 adapter 改为 pipe-backed `WindowsIpcTunIo`；blocking Win32 pipe I/O留在专用线程，Tokio侧只看 bounded channel |
| `src/dialer.rs` | destination-aware loopback/physical TCP 与 UDP binding |
| `src/bin/windows_session_host.rs` | 新增最小参数 parser 和对 library runner 的调用 |
| `src/lib.rs` | target/feature-gated session modules；不新增 C ABI |
| `Cargo.toml` | 新增 required-features=`ffi` binary；补足现有 `windows` Shell、Pipes、IO、FileSystem和 Security Isolation feature flags，不新增 crate |
| `scripts/build_windows.ps1` | 构建、复制并 hash 第三个 Windows artifact |

`TunIo` 继续是 compile-time concrete alias：

```text
Unix    TunIo = RustTunIo
Windows TunIo = WindowsIpcTunIo
```

不增加 trait、factory、fake fd、`windows-vpn` feature、`ipc` feature 或 `tun2socks` feature。

`vcore-windows-session-host.exe` 直接链接同一 VCore crate。第一版接受 package 内 DLL/EXE 的 Rust code duplication，避免增加 package-private DLL ABI。只有产物大小实测成为问题时，才另行决定是否引入内部 export。

### 12.2 OneVCore

| 文件/区域 | 计划 |
| --- | --- |
| `build_scripts/sync_vcore_windows.ps1` | 要求、校验、复制第三 artifact；architecture/static CRT checks覆盖三个文件 |
| `windows/app.cmake` | 安装 Session Host beside Flutter executable |
| `build_scripts/package_windows_msix.ps1` | package completeness gate加入第三文件；继续禁止 active VPN package replacement |
| `windows/packaging/msix/AppxManifest.xml.in` | 不加入 `LoopbackAccessRules`；注册 `AppListEntry="none"` 的 full-trust `SessionHost` Application，不注册 StartupTask/protocol |
| `build_scripts/tests/test_windows_msix_contract.py` | 固定三 artifact、无 rules/exemption、provider activation不变 |
| `lib/core/ffi/windows_native_api.dart` | 预期无 wire/API 变化；仅在响应语义实际变化时修改测试，不新增 method |
| `lib/service/xray/metrics/*` | 保持现有 HTTP Controller路径；不增加 Windows-specific transport |
| `lib/service/vpn/*` | profile/session-record/state semantics保持；现有 connectivity start 幂等修复作为独立前置变更保留 |

Session Host 是包内普通 full-trust executable，不显示在 App list，不成为第二个 StartupTask，也不处理 URI。

## 13. 分阶段实施

### Phase 0：可删除 process/pipe spike — PASS

2026-08-23 在 Windows 11 ARM64 build 26200.9168、Rust 1.98、`windows = 0.62.2`、开发签名 package `OneVCore.SessionHostSpike_1.0.0.0_arm64__r64v7h3q1b2jt` 上完成。最终 MSIX SHA-256 为 `a9d1d6046422fb15727ca82c06779e545d482b4fb4d36fe61422ec21f2921105`，Authenticode 状态为 `Valid`。

实测收敛了四个原设计假设：

1. `CreateProcessW` child可以取得 `Package::Current`/`ApplicationData::Current`并在 launcher退出后继续运行，但 unqualified `LOCAL` pipe不会自动跨越它与 AppContainer namespace，因此不作为产品 activation seam。
2. 从 packaged full-trust launcher调用 `FullTrustProcessLauncher` 在本机返回 `0x80010117`，不可作为已验证路径。
3. manifest隐藏 full-trust `SessionHost` Application + `IApplicationActivationManager` 成功返回精确 PID；launcher退出后 Session Host继续运行。
4. AppContainer创建 pipe server并发布 `GetAppContainerNamedObjectPath`，Session Host以 `\\.\pipe\Sessions\1\AppContainerNamedObjects\<sid>\...` qualified name连接成功。反向 full-trust server、unqualified同包访问和 full-trust端动态推导 package SID均未成立，不能保留为产品假设。

最终通过项：

- AppContainer control/data两条 pipe双向通信；
- 最小 IPv4、IPv6 与 1500-byte frame；
- 100,002 frames、150,000,060 bytes单向 payload全部逐帧 echo，无 corruption；
- 2,699 ms，单向 payload throughput `52.98 MiB/s`（约 444 Mbit/s）；
- 双方均观察 peer EOF/broken-pipe；
- unpackaged same-user client对两个 unqualified `LOCAL` name均为 `ERROR_FILE_NOT_FOUND (2)`；
- transfer前 Session Host为 201 handles / 8 threads / 2,543,616 private bytes，AppContainer client为 281 / 11 / 3,874,816；
- launcher退出后 Session Host存活，Stop后双方退出；
- `CheckNetIsolation` exemption列表前后为空；
- package、process、LocalState、临时源码和 `%TEMP%`目录已全部删除。

Phase 0因此通过，但通过的是“Provider server + qualified AppContainer path + hidden Application activation”架构，而不是初始的“Session Host server + CreateProcess + custom DACL”架构。后续阶段必须按实测结果实现。

### Phase 1：可测试基础模块 — PASS

2026-08-23 已完成 bounded control/data codec、strict rendezvous/qualified path、physical binding DTO，以及 Windows destination-aware loopback socket policy。`Dialer` 只对解析后的 loopback IP跳过 physical source/interface；DIRECT UDP按 IPv4/IPv6 × loopback/physical最多保留四个 socket class。Windows ARM64 all-feature lib tests为 432 passed / 1 ignored；focused packet-channel 4项和 loopback TCP/UDP测试通过；lib Clippy在显式允许两项既有 Rust 1.98 config style lint后以 `-D warnings`通过。

实施顺序：

1. control length/JSON strictness tests；
2. packet length/truncation/oversize tests；
3. message ordering/state-machine tests；
4. canonical AppContainer leaf name、qualified path和 rendezvous strictness tests；
5. stale/oversize/reparse rendezvous cleanup tests；
6. Dialer loopback TCP test（带虚构 physical binding仍使用 loopback）；
7. Dialer loopback/physical UDP socket-class tests；
8. missing-family 和 non-loopback unbound failure tests；
9. 实现最小 codec、rendezvous、binding DTO和 Dialer policy。

本阶段不改变正式 Provider runtime。

### Phase 2：Session Host

1. 添加第三 binary与静态 CRT build。
2. 严格解析唯一 `--snapshot-token` 参数，拒绝 extra args。
3. 获取 package identity/LocalState，等待并验证 Provider rendezvous，再作为 blocking Win32 pipe client连接 qualified path。
4. 实现 SessionHello/provider handshake和 timeout；pipe blocking reader/writer留在专用线程，不把 Tokio named-pipe wrapper作为产品前提。
5. 读取并验证现有 snapshot。
6. 把当前 `ProviderRuntime` / `run_vcore` 逻辑迁入 `windows_session.rs`。
7. 用 `WindowsIpcTunIo` 调用现有 `PreparedCore::prepare_config` / `start_tun`。
8. 保持 Controller、GeoData、所有代理 graph和同步 stop。
9. 使用独立 session log。
10. 在 provider 尚未切换时完成 host-only tests。

### Phase 3：Provider 变为 packet gateway

1. 保留现有 WinRT transport/wake/buffer code。
2. 用 AppContainer-local packet-channel server替换 `WindowsTunIo`/`ProviderRuntime`，并原子发布 rendezvous。
3. `Encapsulate` 只复制并 try-queue ingress。
4. data reader填充 egress并触发 empty-to-nonempty wake。
5. ProviderHello 发送 token和 physical binding。
6. 等待 RuntimeReady 后才 `StartWithMainTransport`。
7. EOF/RuntimeFailed/framing error接入现有 fail-closed worker。
8. Disconnect 发送 Stop、等待 bounded Stopped、关闭 pipe和 transport。
9. 删除 provider 内 `Config`、`GeoDataManager`、`PreparedCore`、`RunningCore`依赖。
10. 不保留 runtime fallback或第二 packet path。

### Phase 4：OneVCore package integration

1. Windows builder输出三个 artifact。
2. sync/CMake/package tests先 red，随后接入 Session Host。
3. `startVpn` 在 profile connect前通过 `IApplicationActivationManager` 激活隐藏 Session Host、取得并持有精确 process handle；失败路径只清理该 process。
4. 生成无 `LoopbackAccessRules` 的下一版开发 MSIX；版本必须高于当前已安装版本。
5. 验证签名 `Valid`、artifact architecture、static CRT、package identity和 in-place disconnected upgrade。
6. 确认现有 Roaming config、snapshot、StartupTask state和单一 VPN profile保留。

### Phase 5：功能验收

使用不含真实凭据的 committed config做基础回归；真实节点只用本地临时 YAML，不进入日志、文档或提交。

必须通过：

- VLESS/XHTTP TLS、REALITY；
- AnyTLS TCP/UoT；
- SOCKS5 CONNECT/UDP ASSOCIATE；
- heterogeneous/同类无环链；
- DIRECT；
- Windows DNS namespace、TCP/UDP DNS；
-普通 UDP/NTP；
- IPv4/IPv6 fake ICMP；
- GeoData当前行为；
- TUN traffic snapshot。

Local SOCKS5 fixture固定监听 `127.0.0.1:1080`，由测试 fixture 自行成对绑定 physical source/interface；测试后删除。验证 no-auth CONNECT和 `udp: true` UDP ASSOCIATE。VCore 不接管 fixture lifecycle。

Metrics 验收：

1. 错误 Bearer secret 返回 401；
2. 持续下载时 `up/down` 与 totals非零；
3. 空闲完成一秒窗口后 speed回到 `0 B/s`；
4. Flutter退出后数据面与 Controller继续工作；
5. Flutter重启后恢复查询；
6. reconnect后四字段从零开始；
7. Stop后 Controller不可访问。

### Phase 6：lifecycle、pressure 与升级

- Provider crash；
- Session Host/VCore crash；
- packet framing fault；
- external SOCKS fixture退出；
- physical adapter disable/network identity变化；
- explicit Stop与超时路径；
- rapid reconnect 10/10，每轮 Provider和 Session Host PID都更换；
- 10 分钟 TCP DNS + UDP NTP active pressure；
- 100 MiB以上持续 transfer；
- queue-full为 0；
- handles、threads、private memory无持续上升 slope；
- disconnected in-place MSIX upgrade；
- clean uninstall后 package、process、LocalState、StartupTask、routes和 profile均清理。

性能使用同机相对基线：新 packet-channel路径 sustained throughput不得低于当前 provider内嵌路径的 80%。若未达到，先定位 copy、pipe buffer和调度；只有有测量证据证明 named pipe 不够时，才提出 shared-memory ADR。

### Phase 7：最终发布门禁（延期）

本阶段不在本轮执行：

- Windows 10 22H2 build 19045；
- 原生 x64 Windows；
- 真实物理 IPv6；
- ARM64/x64 Store bundle；
- WACK；
- Partner Center identity/publisher；
- restricted-capability approval；
- Store submission。

## 14. 自动化与实机测试

### 14.1 VCore focused checks

```powershell
cargo fmt --all -- --check
cargo test --all-features --all-targets
cargo clippy --all-features --all-targets -- -D warnings
cargo test --manifest-path crates/vcore-netstack/Cargo.toml --all-targets
cargo clippy --manifest-path crates/vcore-netstack/Cargo.toml --all-targets -- -D warnings
powershell -File scripts/build_windows.ps1 -Architecture arm64
```

另需检查：

- 三个 artifact 的 PE machine和 static CRT；
- `vcore.dll` 既有四个 export不变；
- C header不新增 Session Host ABI；
- default/non-Windows build不引用 Win32 pipe/security API；
- `git diff --check`。

### 14.2 OneVCore focused checks

```powershell
flutter analyze
flutter test test/core/ffi/windows_native_api_test.dart
flutter test test/service/vpn/connectivity_test.dart
flutter test test/service/xray/vcore_runtime_bundle_test.dart
python -m unittest OneVCore/build_scripts/tests/test_windows_msix_contract.py
python -m unittest OneVCore/build_scripts/tests/test_windows_packaging.py
dart run tool/check_layer_dependencies.dart
```

再运行 Windows package parser/schema、签名、artifact hash和安装检查。全量 Flutter/Python suite中的既有环境问题必须与本次回归分开记录，不得伪装成通过或本次缺陷。

### 14.3 实机证据规则

- 自动化 host test不能证明 AppContainer/full-trust IPC。
- cross build不能证明原生 x64。
- x64 emulation不能替代原生 x64。
- 虚拟 IPv6不能替代物理 IPv6。
- 所有 PASS 必须记录 OS build、architecture、package identity/version、VCore revision、artifact SHA-256、命令和结果。
- 未执行项明确写 `NOT RUN` 或 `deferred`。

## 15. Packaging 合同

Windows package最终包含：

```text
OneVCore.exe
vcore.dll
vcore-windows-vpn-host.exe
vcore-windows-session-host.exe
```

要求：

- 三个 native artifact architecture与 package一致；
- Rust产物 static CRT；
- Session Host不显示在 App list；
- Session Host不注册 StartupTask、protocol handler或 VPN background task；
- provider COM activation仍来自 `vcore.dll`；
- manifest无 `uap4:LoopbackAccessRules`；
- package无 `wintun.dll`；
- `CheckNetIsolation LoopbackExempt -s` 中不存在 OneVCore exemption；
- `-Install` 继续拒绝 active VPN和同/降版本，使用 in-place update而非卸载。

## 16. 文档与 ADR

设计阶段新增 proposed ADR：

- `VCore/docs/adr/0003-run-windows-runtime-in-a-full-trust-session-host.md`；
- `OneVCore/docs/adr/0007-run-windows-runtime-in-a-full-trust-session-host.md`。

Phase 0通过后两份 ADR已改为 `accepted`。实现各阶段同步更新：

- `VCore/CONTEXT.md`、`OneVCore/CONTEXT.md`；
- `VCore/AGENTS.md`、`OneVCore/AGENTS.md`；
- `VCore/README.md`；
- `VCore/docs/UWP_TUN_RESEARCH.md`；
- `VCore/docs/tun-platform.md`；
- `VCore/docs/controller-api.md`；
- `VCore/docs/invoke-api.md`；
- `VCore/docs/acceptance.md`；
- `OneVCore/docs/VCORE_INTEGRATION.md`；
- `OneVCore/docs/WINDOWS_PHASE3.md`；
- packaging和升级 contract docs。

历史 AppContainer loopback矩阵保留为研究证据；不得把 named-pipe实测改写成 TCP loopback平台保证。

## 17. 回滚

- Phase 0失败：删除 spike，正式源码不动。
- Phase 1–4失败：回退对应源码提交，继续使用最后一个 provider-runtime开发包。
- 数据面切换后的 package问题通过修复或源码回退后发布更高 MSIX版本处理。
- 不在同一 binary中保留旧 runtime path。
- 不支持 MSIX降版本或跨 identity自动迁移。
- 任何 update前先显式断开 VPN。

## 18. 完成定义

只有全部满足下列条件，才可称 Windows Session Runtime重构完成：

- Provider源码不再依赖 `Config`、`PreparedCore`、`RunningCore` 或 proxy graph。
- Session Host是 Windows TUN VCore runtime的唯一 owner。
- Provider作为 AppContainer-local server，与 Session Host只通过 version-1 packet channel和最小 rendezvous通信。
- Invoke v5、schema 11、bridge v1、snapshot token和 Dart API未改变。
- VLESS、SOCKS5、AnyTLS、DIRECT、DNS、rules、GeoData、sniffer与 chains通过回归。
- `127.0.0.1:1080` SOCKS5 TCP/UDP路径通过。
- Controller metrics、restart reset和 Stop关闭通过。
- crash、network change、rapid reconnect、pressure和 disconnected upgrade通过。
- 新路径达到相对性能门禁，queue-full为 0且资源无上升 slope。
- 下一版 MSIX无实验性 loopback rules、Wintun或 exemption。
- 三个 artifact、签名、architecture、static CRT和清理 contract通过。
- docs、CONTEXT、ADRs和 acceptance evidence与代码一致。
- throwaway package、fixture、临时源码、LocalState和进程全部清理。
- Phase 3B延期项目仍清楚标记为 deferred，而非暗示发布完成。

## 19. 后续仍需取得的事实

Phase 0已解决 process activation、namespace qualification、unpackaged isolation、framing和初始 throughput。正式阶段仍必须实测：

1. 相同 workload下新 packet channel相对当前 provider内嵌数据面的吞吐与 CPU比例，最终门禁仍为至少 80%。
2. `IApplicationActivationManager` 从真实 Flutter worker-isolate host bridge调用时返回的 PID/handle、错误和 package-update行为。
3. 动态 Windows session ID（不能硬编码 Phase 0 的 `1`）与 qualified AppContainer path在注销/登录和多 session场景中的行为。
4. 真实 `VpnChannel` callback pressure下 blocking Win32 pipe worker、256 queues和 Decapsulate wake的组合行为。
5. Provider crash、Session Host crash、network change、rapid reconnect与 package upgrade下 rendezvous清理是否按契约收敛。

任一事实不成立时，停在对应 gate修正当前阶段；不得把失败隐藏在兼容 fallback中。

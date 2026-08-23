# Windows Session Runtime 重构计划

> 状态：已完成设计访谈，等待 Phase 0 可行性验证。
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
| Windows Session Host | 一次 VCore TUN runtime、Controller、GeoData registration、packet-channel server | `VpnChannel`、Windows routes、外部 SOCKS5 service |
| Windows VPN provider | `VpnChannel`、WinRT buffers、callback queues、physical network identity、network monitor | YAML 业务解析、proxy graph、Controller、GeoData |
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
4. 对 disconnected profile，host bridge 从 package installed location 解析固定的 `vcore-windows-session-host.exe`。
5. 使用 `CreateProcessW` 直接启动，不经过 shell、不搜索 `PATH`，只传递：

   ```text
   --snapshot-token onevcore-v1:<sha256>
   ```

6. Session Host 获取自己的 package identity 和 LocalState，创建 first-instance control/data pipes。
7. host bridge 发送 `LauncherProbe` 并在 5 秒内等待 `LauncherReady`。
8. host bridge 更新单一 VPN profile，然后调用 `ConnectProfileAsync`。
9. Windows 激活 Provider。Provider 在安装 VPN routes 前选择 `Physical network binding`。
10. Provider 连接 control pipe，发送 `ProviderHello`：internal protocol version、profile token 和 immutable physical binding。
11. Session Host 严格比较 command-line token、handshake token 和 snapshot digest，读取 YAML并启动 VCore。
12. Controller、GeoData、proxy graph 和 `WindowsIpcTunIo` 全部成功后，Session Host 返回 `RuntimeReady`。
13. Provider 才调用 `StartWithMainTransport`，安装 network callback 并 arm fail-closed worker。
14. `ConnectProfileAsync` 成功后，Flutter 按现有事务写入 `run/start.json`。

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

这些文档不能代替当前 package 模型的实机结果。正式编码前必须完成 Phase 0，同机验证 AppContainer Provider 方向、full-trust Session Host 方向、package SID DACL 和 parent-exit 生命周期。

### 7.2 两条 pipe

Session Host 是两条 pipe 的 server：

```text
\\.\pipe\LOCAL\OneVCore.<sha256(PFN)>.Vpn.Control.v1
\\.\pipe\LOCAL\OneVCore.<sha256(PFN)>.Vpn.Data.v1
```

- PFN 使用 `Package::Current().Id().FamilyName()` 的 UTF-8 bytes 做 SHA-256。
- PFN digest 避免 Dev/Store identity 的命名冲突；DACL负责拒绝 unpackaged client。
- control pipe 与 data pipe 分开，控制消息不受 packet backpressure 阻塞。
- server 使用 first-instance 与 reject-remote-client 语义；control first instance 同时是 Session Host 单实例锁。

### 7.3 ACL

Session Host 创建 security descriptor，只允许：

- pipe owner；
- 当前 package 的 AppContainer/package SID；
- Windows 为对象管理所必需的系统主体。

不得使用“当前用户全部进程可访问”的宽泛 DACL。Phase 0 必须证明：

- packaged Flutter probe 可以完成 launcher handshake；
- AppContainer client 可以完成 provider handshake/data I/O；
- 独立 unpackaged same-user client 被拒绝；
- 不需要 `CheckNetIsolation` exemption。

snapshot token 不是 secret。认证依靠对象 ACL，token 只防止错误 session/配置交叉连接。

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
LauncherProbe { version, snapshotToken }
LauncherReady { version }
ProviderHello { version, snapshotToken, physicalBinding }
RuntimeReady { version }
RuntimeFailed { code, redactedMessage }
Stop
Stopped { packetCounters }
```

Timeout：

- launcher/process ready：5 秒；
- provider handshake + VCore prepare/start：15 秒；
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
| `src/windows_host.rs` | 在现有 `startVpn` 内增加固定 Session Host launch/ready/rollback；六个 bridge method不变 |
| `src/windows_snapshot.rs` | 复用 publication/verification；向 Session Host runner提供 crate 内入口 |
| `src/windows_packet_channel.rs` | 新增 pipe naming、ACL、control/data codec、provider/session endpoints、strict DTO |
| `src/windows_session.rs` | 新增 Session Host 主生命周期、snapshot读取、VCore prepare/start/stop、error convergence |
| `src/windows_log.rs` | 提取 bounded per-process logger |
| `src/platform/windows_tun_io.rs` | 从同进程 adapter 改为 pipe-backed `WindowsIpcTunIo` |
| `src/dialer.rs` | destination-aware loopback/physical TCP 与 UDP binding |
| `src/bin/windows_session_host.rs` | 新增最小参数 parser 和对 library runner 的调用 |
| `src/lib.rs` | target/feature-gated session modules；不新增 C ABI |
| `Cargo.toml` | 新增 required-features=`ffi` binary；补足现有 `windows` security/process feature flags，不新增 crate |
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
| `windows/packaging/msix/AppxManifest.xml.in` | 不加入 `LoopbackAccessRules`；Session Host不注册可见 Application/StartupTask/protocol |
| `build_scripts/tests/test_windows_msix_contract.py` | 固定三 artifact、无 rules/exemption、provider activation不变 |
| `lib/core/ffi/windows_native_api.dart` | 预期无 wire/API 变化；仅在响应语义实际变化时修改测试，不新增 method |
| `lib/service/xray/metrics/*` | 保持现有 HTTP Controller路径；不增加 Windows-specific transport |
| `lib/service/vpn/*` | profile/session-record/state semantics保持；现有 connectivity start 幂等修复作为独立前置变更保留 |

Session Host 是包内普通 full-trust executable，不显示在 App list，不成为第二个 StartupTask，也不处理 URI。

## 13. 分阶段实施

### Phase 0：可删除 process/pipe spike

正式源码修改前，在 `%TEMP%` 创建独立最小 MSIX。使用固定的 `cert/OneVCore.Phase0.pfx`，不生成、导入或删除证书。

必须验证：

1. packaged full-trust launcher 用 `CreateProcessW` 启动固定 child。
2. child 内 `Package::Current` 与 `ApplicationData::Current` 成功。
3. launcher 退出后 child 继续运行。
4. AppContainer client 与 full-trust server 完成 control/data 两条 `LOCAL` pipe 双向通信。
5. package-SID DACL允许 packaged launcher和 AppContainer，拒绝 unpackaged same-user client。
6. IPv4/IPv6 最小 packet 与 1500-byte packet framing正确。
7. 十万次双向 frame 无 corruption。
8. 任一端退出，另一端在 bounded 时间观察 EOF。
9. 记录 throughput、packet rate、CPU、handles、threads、private memory。
10. 全程无 `CheckNetIsolation` exemption。

若 `CreateProcessW` 无法保留 package identity或独立生命周期，停止并把启动机制重新决策为 manifest `windows.fullTrustProcess` + `FullTrustProcessLauncher`；不得静默混用两种方式。

完成后删除 package、进程、LocalState、临时源码和测试文件。Phase 0 未通过时正式重构停止。

### Phase 1：可测试基础模块

按 TDD 顺序：

1. control length/JSON strictness tests；
2. packet length/truncation/oversize tests；
3. message ordering/state-machine tests；
4. PFN pipe-name determinism tests；
5. security descriptor ownership/cleanup tests；
6. Dialer loopback TCP test（带虚构 physical binding仍使用 loopback）；
7. Dialer loopback/physical UDP socket-class tests；
8. missing-family 和 non-loopback unbound failure tests；
9. 实现最小 codec、ACL builder、binding DTO和 Dialer policy。

本阶段不改变正式 Provider runtime。

### Phase 2：Session Host

1. 添加第三 binary与静态 CRT build。
2. 严格解析唯一 `--snapshot-token` 参数，拒绝 extra args。
3. 获取 package identity/LocalState，创建 first-instance pipes。
4. 实现 launcher handshake、provider handshake和 timeout。
5. 读取并验证现有 snapshot。
6. 把当前 `ProviderRuntime` / `run_vcore` 逻辑迁入 `windows_session.rs`。
7. 用 `WindowsIpcTunIo` 调用现有 `PreparedCore::prepare_config` / `start_tun`。
8. 保持 Controller、GeoData、所有代理 graph和同步 stop。
9. 使用独立 session log。
10. 在 provider 尚未切换时完成 host-only tests。

### Phase 3：Provider 变为 packet gateway

1. 保留现有 WinRT transport/wake/buffer code。
2. 用 packet-channel client替换 `WindowsTunIo`/`ProviderRuntime`。
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
3. `startVpn` 在 profile connect前 launch/probe host，并在失败路径只清理本次 process handle。
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

Phase 0通过后把两份 ADR改为 `accepted`。实现各阶段同步更新：

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
- Provider与 Session Host只通过 version-1 packet channel通信。
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

## 19. 当前待验证事实

以下不是继续讨论的产品决策，而是 Phase 0必须取得的事实：

1. 当前目标 Windows build上，`CreateProcessW` 启动的包内 child是否取得 package identity。
2. Flutter launcher退出后 child是否保持运行。
3. package-SID DACL是否同时允许 packaged full-trust launcher和 AppContainer Provider，并拒绝 unpackaged same-user process。
4. `tokio` named pipe在当前 AppContainer/full-trust方向的实际行为。
5. named pipe相对当前内嵌 packet path的吞吐、CPU和资源成本。

任一事实不成立时，停在对应 gate重新决策；不得把失败隐藏在兼容 fallback中。

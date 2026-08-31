# Windows 会话运行时

Windows package 只有一个主 Application，但每个 VPN 会话仍由独立的完全信任 Session Host 独占完整 VCore 运行时。AppContainer Provider 只负责 Windows VPN 平台资源、原始包转发和失败关闭；系统中不存在 Provider 内嵌运行时的备用路径。

## 参与者与所有权

```text
前台宿主（完全信任）
  ├─ VCoreInvoke
  └─ VCoreWindowsVpnInvoke
       ├─ Session Snapshot / profile
       └─ ConnectProfileAsync
              │ Windows 激活
              ▼
vcore-windows-vpn-host.exe + vcore.dll（AppContainer）
  ├─ VpnChannel / 路由 / DNS / 物理网络
  ├─ VpnPacketBuffer / 有界回调队列 / 失败关闭
  └─ FullTrustProcessLauncher
              │ 无参数激活
              ▼
vcore-windows-session-host.exe
  ├─ 校验不可变 Session Snapshot
  ├─ 可选 Windows session backend / Job Object
  ├─ PreparedCore / RunningCore
  ├─ DNS / 规则 / GeoData / 嗅探器 / select 代理组
  ├─ VLESS / SOCKS5 / AnyTLS / DIRECT
  └─ 运行时 Controller（TUN 流量 / 代理组选择）
              ▲
              └─ 同包控制管道 + 数据管道
```

| 参与者 | 拥有 | 不拥有 |
| --- | --- | --- |
| 前台宿主 | 用户命令、会话记录、UI 状态 | TUN 运行时、包通道、Provider 状态 |
| Windows 桥接 | Session Snapshot、profile、连接/断开命令 | 数据包、代理流、Session Host 进程 |
| Session Host | 单次 VCore 运行时、可选 session backend、Controller、GeoData、包客户端 | `VpnChannel`、路由、进程业务配置 |
| Provider | `VpnChannel`、WinRT 缓冲区、路由、物理绑定、管道服务端、网络监控、Session Host 激活 | YAML、代理图、Controller、GeoData、backend 描述 |
| SOCKS 服务 | 自身监听器、外层 socket 和绕过策略 | VCore 代理图和 Windows profile |

Session Host 每次连接新建一个进程，不常驻、不复用运行时，也不处理 URI 或 StartupTask。

## 快照与 profile

- Windows 只维护一个同包 `VCore` profile。
- 桥接先用当前解析器验证 TUN 配置、四个网络地址和可选 backend，再发布单文件内容寻址 Session Snapshot：

  ```text
  vcore-session-v2:<64 lowercase sha256>
  LocalState/vcore/windows/sessions/<sha256>.json
  ```

- Snapshot revision 2 保存完整 VCore YAML（包括代理组及其 `default-selected`），以及可选的有序 `sessionBackend.processes`；每项只有规范 package-relative executable path 和 argv 数组。
- token 覆盖 YAML、进程顺序、路径和参数。参数引用的文件由调用方保持存在且不可变，VCore 不读取或摘要其内容。
- profile custom configuration 是最大 1 KiB 的严格 JSON，包含修订版 3、规范 Session token、顶层 IPv6 开关和 TUN/DNS 的 IPv4/IPv6 地址。
- custom configuration 不包含 YAML、backend 描述、Controller secret、PID 或管道路径。
- `startVpn` 的四个地址始终严格必填并经过验证；顶层 `ipv6: false` 时，Provider 忽略两个 IPv6 地址，只安装 IPv4 地址、路由和 DNS。
- 活动 profile 只有在 token、IPv6 开关和四个地址完全相同时才幂等；任何变化都必须先 Stop。
- 读取 Snapshot 时校验大小、普通文件、reparse point、内容摘要、规范 JSON及每个 executable。
- TUN 地址、Controller 端口/secret 和 Ping 目标属于运行时字段，不写入用户 RAW YAML。

## 启动顺序

1. 前台宿主调用 `startVpn(configYaml, networkSettings, sessionBackend?)`。
2. 桥接验证配置、四个地址和进程描述，发布不可变 Session Snapshot，并把解析后的顶层 IPv6 开关写入 profile configuration。
3. 桥接写入单一 VPN profile 并调用 `ConnectProfileAsync`；它不启动或持有 Session Host。
4. Windows 激活 AppContainer Provider。
5. Provider 从 profile configuration 取得权威 token，选择物理网络绑定并准备基础资源。
6. Provider 清理陈旧会合记录，通过无参数 `FullTrustProcessLauncher` 激活 Session Host。
7. Session Host 不读取动态命令行参数，等待 Provider 会合记录。
8. Provider 创建控制/数据管道服务端并原子发布会合记录。
9. Session Host 严格解析会合记录，把其中的 token 作为候选值，构造限定对象路径并连接两条管道。
10. Session Host 发送 `SessionHello`；Provider 把候选 token 与 profile token 精确比较后返回 `ProviderHello` 和不可变物理绑定。
11. Session Host 验证 `ProviderHello` 回传同一 token，之后才读取 Snapshot；若存在 backend，则用一个 kill-on-close Job Object 按顺序启动全部进程。
12. Session Host 准备并启动完整 VCore 运行时、静态代理组状态和 Controller。
13. Session Host 确认受管进程尚未退出后返回 `RuntimeReady`。
14. Provider 调用 `StartWithMainTransport` 并启动失败关闭监视器。
15. 连接成功后，桥接向前台宿主返回当前系统 VPN 状态。

任一步失败都必须关闭包通道并收敛为 Disconnected，只返回有界脱敏错误；未完成握手的 Session Host 最多等待 15 秒后退出。

## 会合记录

`LocalState/vcore/windows/rendezvous.json` 最大 4 KiB：

```json
{
  "protocolVersion": 1,
  "snapshotToken": "vcore-session-v2:...",
  "objectPath": "AppContainerNamedObjects\\S-1-15-2-...",
  "controlLeaf": "VCore.Vpn.Control.v1",
  "dataLeaf": "VCore.Vpn.Data.v1"
}
```

- Provider 是唯一发布者和清理者；
- 使用同目录暂存文件和原子重命名；
- 只接受规范 token、AppContainer 相对路径和固定 leaf；
- 非普通文件、reparse point、超限或未知字段都会失败关闭；候选 token 与 profile token 的绑定只在双向握手中完成；
- 握手完成后删除，新连接前清理断开状态下的陈旧记录。

## 控制协议

```text
u32 大端序 JSON 长度
严格 UTF-8 JSON
```

- 单帧最大 16 KiB；
- DTO 拒绝未知字段、错误版本和错误顺序；
- 错误码最大 128 字节，脱敏信息最大 4 KiB；
- 不传 YAML、Controller secret、SOCKS 凭据、日志或 Invoke 请求。

版本 1 消息：

```text
SessionHello { version, snapshotToken }
ProviderHello { version, snapshotToken, physicalBinding }
RuntimeReady { version }
RuntimeFailed { version, code, redactedMessage }
Stop { version, packetCounters }
Stopped { version, packetCounters }
```

启动超时 15 秒，有序停止确认超时 10 秒。活动包流没有空闲超时或 heartbeat。

## 数据协议

每个方向只有一个写端：

```text
u16 大端序包长
1..=1500 字节原始 IP 包
```

- EOF、截断、零长度、超限和帧格式错误会停止当前会话；
- 合法帧中的非法 IP 包由原始包解析器局部丢弃；
- wire v1 不包含 batch envelope、方向字节、校验和或压缩；
- 写端只等待首包，然后最多排空 7 个已经位于现有有界队列中的包；
- 不等待计时器或未来数据，低流量单包立即发送；
- 两端读端使用 64 KiB 缓冲区并逐帧校验；
- 编码缓冲区在任务内复用，单次最多写入 `8 × 1502` 字节。

## 回调队列

Provider 两侧容量均为 256：

```text
Encapsulate
  -> 复制包
  -> try_send 入站队列
  -> 包写端

数据读端
  -> 有界出站队列
  -> 空到非空唤醒
  -> Decapsulate 排空
```

回调不等待管道 I/O。队列满时只丢当前包并计数。Session Host 的 `WindowsTunIo` 使用同样的有界通道并接入 `TunRuntime`；流量统计继续按原始 IP TUN 边界计算。

## 物理网络绑定

Provider 选择并持有：

- 适配器 GUID；
- profile 和 network identity；
- 可用地址族的源 IP 和非零接口索引。

Session Host 只消费这份不可变绑定。每个非回环 socket 必须同时设置源地址和接口选项。只有配置中显式使用 `127.0.0.0/8` 范围内的 IPv4 字面量或 `::1` 的本地出站可以跳过；物理代理服务器的域名在准备阶段解析到任何回环地址都会失败关闭。地址族缺失、bind 失败或 setsockopt 失败时，当前连接失败关闭。

Provider 订阅网络变化，等待 2 秒消抖后复验适配器、地址和 identity。任一变化就停止会话，不迁移 socket、不重选网卡、不自动回退。

## Windows session backend

`sessionBackend` 可以省略；存在时包含 `1..=8` 个进程。每个进程只声明：

```json
{
  "executableRelativePath": "bin\\proxy-core.exe",
  "arguments": ["run", "--mode", "vpn"]
}
```

- executable 必须是 package installed location 内不经过 reparse point 的规范 `.exe` 相对路径；
- argv 项数、单项大小、总大小和最终 UTF-16 command line 均有界；
- 不经过 shell，不展开环境变量，工作目录固定为 package installed location；
- Session Host 使用 `CreateProcessW(CREATE_SUSPENDED)`，先加入设置了 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` 的 Job，再恢复主线程；
- 所有进程都是关键进程；任一退出都会停止 VCore、终止同 Job 中的其余进程并使 Provider 失败关闭；
- Stop 先停止 VCore，再终止 Job，确认活动进程归零后才返回 `Stopped`；
- 第一版不提供 port、UDP、readiness、heartbeat、restart、environment、working directory 或单进程控制；
- `RuntimeReady` 只表示进程仍存活且 VCore 已启动，不表示进程内部协议已就绪。

## Controller 与本地 SOCKS

- Controller 由 Session Host 监听完全信任的回环地址；
- `RuntimeReady` 前必须完成绑定，失败则连接失败；
- 前台宿主持有配置中的端口和 secret，并调用 `GET /traffic`、`GET /group`、`GET /group/{name}`、`GET /proxies/{name}` 或 `PUT /proxies/{name}`；
- 配置代理组与 Controller 时 secret 必填并保护全部路由；仅有 TUN 流量 Controller 时 secret 仍可省略；
- 代理组选择属于 Session Host 中实际 Running Session 的内存状态，不经过 Windows bridge、Provider 控制管道或 Session Snapshot 写回；
- 成功切换只影响之后新建的物理 TCP、UDP 和 DNS transport，不迁移既有连接、UDP association、DNS 状态或 TCP pool，也不执行自动 failover；
- 宿主如需跨 VPN session 保留选择，必须自行持久化，并在下次 `startVpn` 的 YAML 中注入对应 `default-selected`；
- 前台宿主退出后 Controller 和运行时继续，重新启动后恢复查询；
- Stop 关闭 Controller，销毁本次代理组选择；下一会话重新采用 YAML 初始选择并从零计数；
- 回环 SOCKS5 是普通 VCore 出站；其服务可以由外部宿主管理，也可以恰好运行在 session backend 中，但 VCore 不从 backend 描述推断端口或 readiness；
- 单个 SOCKS 流失败不停止 VPN。

## 生命周期

| 事件 | 结果 |
| --- | --- |
| 前台宿主退出 | Provider、Session Host 和运行时继续 |
| 前台宿主重启 | 以系统 profile 为权威恢复状态和 Controller 查询 |
| Provider 退出 | Windows 清理 VPN，Session Host 因 EOF 退出 |
| Session Host 退出 | Job 清理受管进程，Provider 失败关闭并停止 VPN |
| 任一受管进程退出 | 停止 VCore和其余受管进程，Provider 失败关闭 |
| 物理网络变化 | 消抖后停止 VPN |
| 管道非法或 EOF | 停止当前会话 |
| 显式 Stop | Disconnect -> Stop -> 有界确认 -> channel Stop |
| 本地 SOCKS 流失败且服务进程仍存活 | 只失败当前流 |
| Controller 绑定失败 | 启动失败，profile 不进入 Connected |
| Controller 切换代理组 | 当前 Session Host 原子更新选择；既有 transport 保持原路径 |

桥接不持有或终止 Session Host 进程；启动失败由 Provider 的 Connect 清理路径收敛，显式 Stop 通过系统 profile 断开。

## 安装包契约

```text
HostApplication.exe
vcore.dll
vcore-windows-vpn-host.exe
vcore-windows-session-host.exe
[optional package-local managed executables]
```

- 产物架构与安装包一致，Rust 产物使用静态 CRT；
- Session Host 不显示在应用列表，不注册 StartupTask、URI 或 VPN background task；
- Provider activation 来自 `vcore.dll`；
- Manifest 包含 `networkingVpnProvider` 和 `runFullTrust`；
- 不使用产品级 loopback exemption；
- 安装或升级前必须断开活动 VPN，版本必须递增。

当前实测范围和未完成发布门禁见 [验收矩阵](acceptance.md)。

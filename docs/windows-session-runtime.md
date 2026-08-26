# Windows 会话运行时

Windows 每个 VPN 会话由一个隐藏的完全信任 Session Host 独占完整 VCore 运行时。AppContainer Provider 只负责 Windows VPN 平台资源、原始包转发和失败关闭；系统中不存在 Provider 内嵌运行时的备用路径。

## 参与者与所有权

```text
前台宿主（完全信任）
  ├─ VCoreInvoke
  └─ VCoreWindowsVpnInvoke
         │ 激活
         ▼
vcore-windows-session-host.exe
  ├─ 校验不可变快照
  ├─ PreparedCore / RunningCore
  ├─ DNS / 规则 / GeoData / 嗅探器
  ├─ VLESS / SOCKS5 / AnyTLS / DIRECT
  └─ 已鉴权流量 Controller
         ▲
         │ 同包控制管道 + 数据管道
         ▼
vcore-windows-vpn-host.exe + vcore.dll（AppContainer）
  ├─ VpnChannel 生命周期
  ├─ 路由 / DNS / 物理网络
  ├─ VpnPacketBuffer 所有权
  ├─ 有界回调队列
  └─ 失败关闭
```

| 参与者 | 拥有 | 不拥有 |
| --- | --- | --- |
| 前台宿主 | 用户命令、会话记录、UI 状态 | TUN 运行时、包通道、Provider 状态 |
| Windows 桥接 | 快照、profile、Session Host 激活与回滚 | 数据包、代理流 |
| Session Host | 单次 VCore 运行时、Controller、GeoData、包客户端 | `VpnChannel`、路由、外部 SOCKS 服务 |
| Provider | `VpnChannel`、WinRT 缓冲区、路由、物理绑定、管道服务端、网络监控 | YAML、代理图、Controller、GeoData |
| 外部 SOCKS 服务 | 自身监听器、外层 socket 和绕过策略 | VCore 生命周期和 Windows profile |

Session Host 每次连接新建一个进程，不常驻、不复用运行时，也不处理 URI 或 StartupTask。

## 快照与 profile

- Windows 只维护一个同包 `VCore` profile。
- 桥接先用当前解析器验证 TUN 配置和四个网络地址，再发布内容寻址快照：

  ```text
  vcore-v1:<64 lowercase sha256>
  LocalState/vcore/windows/snapshots/<sha256>.yaml
  ```

- profile custom configuration 是最大 1 KiB 的严格 JSON，包含修订版 1、规范快照令牌和 TUN/DNS 的 IPv4/IPv6 地址。
- custom configuration 不包含 YAML、Controller secret、PID 或管道路径。
- 活动 profile 只有在令牌和四个地址完全相同时才幂等；任何变化都必须先 Stop。
- 读取快照时校验大小、普通文件、reparse point 和内容摘要。
- TUN 地址、Controller 端口/secret 和 Ping 目标属于运行时字段，不写入用户 RAW YAML。

## 启动顺序

1. 前台宿主调用 `startVpn(configYaml, networkSettings)`。
2. 桥接验证配置和地址，发布不可变快照并生成 profile configuration。
3. 桥接通过 `IApplicationActivationManager` 激活隐藏 Session Host，只传 `--snapshot-token <token>`。
4. 桥接持有激活返回的精确进程句柄。
5. 桥接写入单一 VPN profile 并调用 `ConnectProfileAsync`。
6. Windows 激活 Provider。
7. Provider 在安装路由前选择物理网络绑定，并创建控制/数据管道服务端。
8. Provider 原子发布会合记录。
9. Session Host 校验命令行令牌和会合记录，构造限定对象路径并连接两条管道。
10. Session Host 发送 `SessionHello`；Provider 返回 `ProviderHello` 和不可变物理绑定。
11. Session Host 读取快照，准备并启动完整 VCore 运行时和 Controller。
12. Session Host 返回 `RuntimeReady`。
13. Provider 调用 `StartWithMainTransport` 并启动失败关闭监视器。
14. 连接成功后，桥接向前台宿主返回当前系统 VPN 状态。

任一步失败都必须关闭包通道、终止本次精确 Session Host、收敛为 Disconnected，并只返回有界脱敏错误。

## 会合记录

`LocalState/vcore/windows/rendezvous.json` 最大 4 KiB：

```json
{
  "protocolVersion": 1,
  "snapshotToken": "vcore-v1:...",
  "objectPath": "AppContainerNamedObjects\\S-1-15-2-...",
  "controlLeaf": "VCore.Vpn.Control.v1",
  "dataLeaf": "VCore.Vpn.Data.v1"
}
```

- Provider 是唯一发布者和清理者；
- 使用同目录暂存文件和原子重命名；
- 只接受规范 AppContainer 相对路径、固定 leaf 和匹配令牌；
- 非普通文件、reparse point、超限、未知字段和令牌不匹配都会失败关闭；
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

Session Host 只消费这份不可变绑定。每个非回环 socket 必须同时设置源地址和接口选项。只有解析后的 `127.0.0.0/8` 和 `::1` 可以跳过；地址族缺失、bind 失败或 setsockopt 失败时，当前连接失败关闭。

Provider 订阅网络变化，等待 2 秒消抖后复验适配器、地址和 identity。任一变化就停止会话，不迁移 socket、不重选网卡、不自动回退。

## Controller 与外部 SOCKS

- Controller 由 Session Host 监听完全信任的回环地址；
- `RuntimeReady` 前必须完成绑定，失败则连接失败；
- 前台宿主持有配置中的端口和 secret，并调用 `GET /traffic`；
- 前台宿主退出后 Controller 和运行时继续，重新启动后恢复查询；
- Stop 关闭 Controller，下一会话从零计数；
- 回环 SOCKS5 是普通 VCore 出站，外部服务的进程、监听器和外层网络绕过由其所有者负责；
- 单个 SOCKS 流失败不停止 VPN。

## 生命周期

| 事件 | 结果 |
| --- | --- |
| 前台宿主退出 | Provider、Session Host 和运行时继续 |
| 前台宿主重启 | 以系统 profile 为权威恢复状态和 Controller 查询 |
| Provider 退出 | Windows 清理 VPN，Session Host 因 EOF 退出 |
| Session Host 退出 | Provider 失败关闭并停止 VPN |
| 物理网络变化 | 消抖后停止 VPN |
| 管道非法或 EOF | 停止当前会话 |
| 显式 Stop | Disconnect -> Stop -> 有界确认 -> channel Stop |
| 外部 SOCKS 流失败 | 只失败当前流 |
| Controller 绑定失败 | 启动失败，profile 不进入 Connected |

桥接回滚只终止本次激活返回的精确进程句柄，不按进程名扫描或清理。

## 安装包契约

```text
HostApplication.exe
vcore.dll
vcore-windows-vpn-host.exe
vcore-windows-session-host.exe
```

- 产物架构与安装包一致，Rust 产物使用静态 CRT；
- Session Host 不显示在应用列表，不注册 StartupTask、URI 或 VPN background task；
- Provider activation 来自 `vcore.dll`；
- Manifest 包含 `networkingVpnProvider` 和 `runFullTrust`；
- 不使用产品级 loopback exemption；
- 安装或升级前必须断开活动 VPN，版本必须递增。

当前实测范围和未完成发布门禁见 [验收矩阵](acceptance.md)。

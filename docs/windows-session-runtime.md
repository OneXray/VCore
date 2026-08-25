# Windows Session Runtime

状态：Windows Session Runtime已实现并在Windows 11 ARM64开发签名package中通过功能、lifecycle、pressure和bounded batching验收。本文描述当前架构；Windows 10、native x64、physical IPv6、WACK和Store发布仍是独立门禁。

## 1. 目标

- AppContainer Provider只拥有Windows VPN平台资源和fail-closed责任。
- 每个VPN session由一个hidden full-trust Session Host独占完整VCore runtime。
- Flutter退出不停止VPN；重启后可恢复system profile、Controller和traffic状态。
- VLESS、SOCKS5、AnyTLS、DIRECT、DNS、rules、GeoData、sniffer、proxy chain和四字段traffic统计保持不变。
- Invoke API v5、schema revision 11、Windows bridge revision 1和Dart start/status/stop接口保持不变。
- Windows只保留一条raw-IP packet path，不提供Provider内嵌runtime fallback。

## 2. 进程与所有权

```text
Flutter foreground (full trust)
  ├─ VCoreInvoke
  └─ VCoreWindowsVpnInvoke
         │ activates
         ▼
vcore-windows-session-host.exe
  ├─ immutable snapshot validation
  ├─ PreparedCore / RunningCore
  ├─ DNS / rules / GeoData / sniffer
  ├─ VLESS / SOCKS5 / AnyTLS / DIRECT
  └─ authenticated Traffic Controller
         ▲
         │ package control + data pipes
         ▼
vcore-windows-vpn-host.exe + vcore.dll (AppContainer)
  ├─ VpnChannel lifecycle
  ├─ routes / DNS / physical network
  ├─ VpnPacketBuffer ownership
  ├─ bounded callback queues
  └─ fail-closed Stop
```

| 参与者 | 拥有 | 不拥有 |
| --- | --- | --- |
| Flutter | 用户命令、session record、UI状态 | VCore TUN runtime、packet channel、Provider state |
| Windows host bridge | snapshot、profile、Session Host activation和rollback | packet data、proxy flow |
| Session Host | 单次VCore runtime、Controller、GeoData、packet client | `VpnChannel`、routes、外部SOCKS service |
| Provider | `VpnChannel`、WinRT buffers、routes、physical binding、pipe servers、network monitor | YAML解析、proxy graph、Controller、GeoData |
| 外部SOCKS service | 自身listener、outer socket和bypass策略 | VCore lifecycle、Windows profile |

Session Host每次session启动一个新process，不常驻、不复用runtime，也不处理URI或StartupTask。

## 3. Snapshot 与 profile

- Windows只维护一个package-owned `OneVCore` profile。
- Host bridge先用当前parser验证TUN config，再发布content-addressed snapshot：

  ```text
  onevcore-v1:<64 lowercase sha256>
  LocalState/vcore/windows/snapshots/<sha256>.yaml
  ```

- Profile只保存canonical token，不保存YAML、Controller secret、PID或pipe path。
- Active profile token相同按现有语义幂等；不同token必须显式Stop，不能hot swap。
- Snapshot读取校验size、regular file、reparse point和content digest。
- Runtime字段如TUN地址、Controller port/secret和Ping目标不写入用户RAW YAML。

## 4. 启动顺序

1. Flutter调用bridge `startVpn(configYaml)`。
2. Bridge验证配置并发布immutable snapshot。
3. Bridge通过`IApplicationActivationManager`激活manifest隐藏的Session Host，只传`--snapshot-token <token>`。
4. Bridge取得并持有精确process handle。
5. Bridge更新单一VPN profile并调用`ConnectProfileAsync`。
6. Windows激活Provider。
7. Provider在安装routes前选择physical binding并创建control/data pipe servers。
8. Provider原子发布strict rendezvous。
9. Session Host校验command token和rendezvous，构造qualified package path并连接两条pipe。
10. Session Host发送`SessionHello`；Provider返回`ProviderHello`和immutable binding。
11. Session Host读取snapshot，prepare/start完整VCore runtime和Controller。
12. Session Host返回`RuntimeReady`。
13. Provider调用`StartWithMainTransport`并arm fail-closed worker。
14. Connect成功后Flutter原子写入`run/start.json`。

任一步失败都必须关闭packet channel、停止本次精确Session Host process、收敛Disconnected并返回有界脱敏错误。

## 5. Rendezvous

`LocalState/vcore/windows/rendezvous.json`最大4 KiB，只包含：

```json
{
  "protocolVersion": 1,
  "snapshotToken": "onevcore-v1:...",
  "objectPath": "AppContainerNamedObjects\\S-1-15-2-...",
  "controlLeaf": "OneVCore.Vpn.Control.v1",
  "dataLeaf": "OneVCore.Vpn.Data.v1"
}
```

- Provider是唯一publisher和cleanup owner。
- 使用同目录staging + atomic rename。
- 只接受canonical AppContainer relative path、固定leaf和匹配token。
- 非regular file、reparse point、oversize、unknown field或token mismatch全部fail closed。
- Handshake完成后删除；stale disconnected record在新start前清理。

## 6. Control protocol

Frame：

```text
u32 big-endian JSON length
UTF-8 strict JSON
```

- 最大16 KiB。
- DTO拒绝unknown fields和错误version/order。
- Error code最大128 bytes，redacted message最大4 KiB。
- 不传YAML、Controller secret、SOCKS credential、日志或任意Invoke request。

Version 1消息：

```text
SessionHello { version, snapshotToken }
ProviderHello { version, snapshotToken, physicalBinding }
RuntimeReady { version }
RuntimeFailed { version, code, redactedMessage }
Stop { version, packetCounters }
Stopped { version, packetCounters }
```

Startup timeout 15秒，orderly Stop ack timeout 10秒；active packet stream没有idle timeout或heartbeat。

## 7. Data protocol 与 batching

每方向单writer：

```text
u16 big-endian packet length
1..=1500 raw-IP bytes
```

- EOF、truncated frame、zero/oversize length和framing violation终止session。
- 合法frame中的无效IP packet由现有raw-IP parser局部拒绝。
- Wire protocol没有batch envelope、direction byte、checksum或compression。
- Writer只等待第一包，然后最多drain 7个已经位于现有bounded queue中的packet，一次写入连续v1 frames。
- Writer不等待timer或未来packet，低流量单包立即发送。
- 两端reader使用64 KiB buffer并继续逐frame严格解析。
- Encoding buffer在task内复用，batch最大wire size为`8 × 1502` bytes。

Production-shaped Tokio 1.52.3 microbenchmark在本机从262.3提升到627.4 MiB/s；该数据是纯IPC证据，不等于package或端到端代理吞吐。实际记录见验收文档。

## 8. Callback queues

Provider两侧容量保持256：

```text
Encapsulate
  -> copy packet
  -> try_send ingress
  -> packet writer

Data reader
  -> bounded egress
  -> empty-to-non-empty wake
  -> Decapsulate drains
```

Callback永不等待pipe I/O。Queue full只丢当前packet并计数。Session Host侧`WindowsTunIo`也使用bounded channel/queue并接入原有`TunRuntime`；traffic snapshot继续按raw-IP TUN boundary计数。

## 9. Physical binding

Provider选择并持有：

- adapter GUID；
- profile/network identity；
- IPv4 source + nonzero interface index（若可用）；
- IPv6 source + nonzero interface index（若可用）。

Session Host只消费该immutable binding。每个非loopback socket必须成对应用source bind与interface option。仅解析后的`127.0.0.0/8`和`::1`可跳过；缺少family、bind或setsockopt失败则连接fail closed。

Provider订阅network change；2秒debounce后adapter、地址或identity不一致即Stop。首版不迁移socket、不重选网卡、不fallback。

## 10. Controller 与 local SOCKS

- Controller由Session Host监听full-trust loopback。
- `RuntimeReady`之前必须完成bind；失败使Connect失败。
- Flutter继续从session record读取port/secret并查询`GET /traffic`。
- Flutter退出后Controller和runtime继续；Flutter重启后恢复。
- Stop关闭Controller；下一session计数从零开始。
- Local SOCKS outbound是普通VCore SOCKS5配置。VCore不启动、监管或保护外部service；普通flow失败不停止VPN。

## 11. Lifecycle

| 事件 | 结果 |
| --- | --- |
| Flutter退出 | Provider、Session Host和runtime继续 |
| Flutter重启 | System profile为authority，恢复Controller查询 |
| Provider退出 | Windows清理VPN；Session Host由EOF退出 |
| Session Host退出 | Provider fail-closed Stop |
| Physical network变化 | Provider debounce后Stop |
| Malformed/EOF | 当前session停止 |
| Explicit Stop | Disconnect -> Stop -> bounded ack -> channel Stop |
| External SOCKS flow失败 | 只失败该flow |
| Controller bind失败 | Startup失败，profile不进入Connected |

Bridge rollback只终止本次activation返回的精确process handle，不扫描PID或按executable name清理。

## 12. Package contract

Package必须包含：

```text
OneVCore.exe
vcore.dll
vcore-windows-vpn-host.exe
vcore-windows-session-host.exe
```

- Artifact architecture与package一致，Rust产物static CRT。
- Session Host不显示在App list，不注册StartupTask/protocol/VPN background task。
- Provider activation来自`vcore.dll`。
- Manifest包含`networkingVpnProvider`和`runFullTrust`。
- 无产品级loopback exemption。
- Install拒绝active VPN和same/older version，使用in-place update。

## 13. 已完成与延期

Windows 11 ARM64开发身份已完成：

- 完整数据面与Controller/local SOCKS；
- Provider/Session Host crash fail closed；
- rapid reconnect和explicit Stop；
- 10分钟pressure、queue drop 0、资源稳定；
- bounded packet batching；
- foreground退出/恢复；
- disconnected upgrade和签名package；
- routes、record、rendezvous和process清理。

延期发布门禁：

- Windows 10 22H2；
- native x64 Windows；
- physical IPv6；
- WACK；
- Partner Center identity/publisher；
- restricted capability approval；
- Store bundle/submission；
- 多用户/remote-session扩展矩阵。

这些项目不得写成已验证的平台保证。当前命令、hash和结果见 [`acceptance.md`](acceptance.md)。

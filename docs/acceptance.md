# VCore 验收

状态：本文只保留当前契约的可复现证据和未完成门禁。历史API、已退役资源模型、临时fixture名称和第三方实现对比不属于当前验收。

## 1. 证据规则

- PASS必须记录环境、命令、结果和适用范围。
- Host unit/integration tests不能证明物理TUN或package boundary。
- Cross-build不能证明目标设备运行。
- 模拟/虚拟IPv6不能替代physical IPv6。
- x64 emulation不能替代native x64 Windows。
- 外网速度不能替代纯IPC benchmark，反之亦然。
- 未执行项写`NOT RUN`或`deferred`，不得从旧snapshot继承PASS。
- Secret、credential、UUID、key、完整RAW YAML和目标详情不得进入文档、日志或package。

## 2. 当前核心自动化

环境：Windows 11 ARM64 build 26200.9168，Rust 1.98，all features。

最近一次当前数据面变更执行：

```text
cargo test --locked --all-features --lib
  437 passed; 1 ignored

cargo test --locked --all-features --bins
  PASS

cargo clippy --locked --all-features --lib --bins -- -D warnings ...
  PASS

cargo fmt --all -- --check
  PASS

cargo test --manifest-path crates/vcore-netstack/Cargo.toml --all-targets
  17 passed

cargo clippy --manifest-path crates/vcore-netstack/Cargo.toml --all-targets -- -D warnings
  PASS

cargo build --locked --release --all-features --lib --bins
  PASS (native ARM64)
```

Ignored项依赖本机外部资产环境，不属于默认host gate。

Focused gates：

- Strict control/data codec、unknown field、version/order、zero/oversize/truncated frame。
- 8-frame batch只触发一次underlying write，仍可由逐frame reader完整解析。
- Empty、9-packet和oversize batch失败且不产生partial write。
- Windows ingress batch等待第一包，只drain已经ready的packet，不等待第二包。
- Windows packet adapter queue/drop/wake语义。
- Destination-aware Windows source + interface binding与loopback例外。
- Snapshot、rendezvous、session args、host bridge和logging boundary。

## 3. 配置与 Invoke API v5

当前公共contract：

- Invoke API v5，schema revision 11。
- YAML不含`configVersion`或`default-proxy`。
- `configYaml` / `configYamls` inline交付，单份最大256 KiB。
- Unknown field、anchor、alias、自定义tag和历史结构失败。
- 至少一个VLESS、SOCKS5或AnyTLS proxy。
- Proxy name唯一且大小写敏感；`dialer-proxy`引用存在并全图无环。
- `rules`必填，最终`MATCH`必须指向实际proxy name。
- 单公共实例、generation `instanceId`和同步stop/destroy barrier。
- `validateConfig`并发纯校验；`measureDelay`单批次1–5项、最多五个私有worker。
- Android protect只作用于TUN outbound socket并fail closed。

自动化覆盖envelope、payload strictness、生命周期、panic recovery、TUN lease、Unicode byte ABI、config graph、node-only parser、批次busy/顺序/逐项错误和资源释放。

## 4. 协议与数据面

### VLESS / XHTTP / TLS / REALITY

Host和opt-in真实进程harness覆盖：

- VLESS TCP和XUDP。
- XHTTP `packet-up`、`stream-up`、`stream-one`。
- Split download settings及TLS/REALITY继承。
- 普通TLS与REALITY。
- Shared connector并发、cancel/reconnect。
- 错误public key、short ID、certificate和HRR负例。
- Cover target使用ECDSA P-256证书，验证ClientHello公布完整signature schemes。

这证明当前wire baseline，不替代公网节点、任意代理链或物理TUN矩阵。

### SOCKS5

自动化和Windows实机覆盖：

- CONNECT no-auth与username/password。
- UDP ASSOCIATE、IPv4/IPv6/domain relay。
- Relay endpoint锁定、wildcard处理、fragment拒绝。
- Nested proxy graph和最终payload ceiling。
- Control EOF只结束对应association。

### AnyTLS

自动化覆盖v2/v1 negotiation、first stream、idle reuse、SYNACK watchdog、padding update、TCP、UoT v2、cancel和explicit shutdown。本地opt-in真实进程harness已覆盖TCP首流/复用、UDP echo、UoT后再次TCP和session cleanup。公网service矩阵仍为`NOT RUN`。

### DNS / rules / GeoData / sniffer

自动化覆盖：

- 全16-bit qtype、UDP/TCP framing、compression和response identity。
- Typed/opaque cache、negative cache、TTL rewrite和singleflight。
- Ordered nameserver policy、explicit egress、failover、UDP retry和TCP reuse。
- TUN UDP/TCP 53、lazy resolve、fixed selected IP和`no-resolve`。
- Domain/IP/port/network/GeoData rules及精确proxy action。
- GeoSite Domain/Full/Plain/Regex、GeoIP IPv4/IPv6 CIDR、asset corruption、budget和hot swap。
- HTTP/TLS/QUIC sniffer、ECH fail-open、bounded QUIC Initial reassembly和exact replay。
- ICMPv4/v6 Echo、checksum、MTU、options、fragment和queue full。

## 5. Platform adapters

### Apple / Android fd

Host tests覆盖：

- `utun` / `rawIp` framing。
- Borrowed fd duplicate和close ownership。
- Nonblocking requirement。
- IPv4/IPv6 packet boundaries、EOF、invalid packet和partial write。
- Repeated start/stop。

Build scripts可生成Apple XCFramework和Android arm64-v8a/x86_64 library。当前文档不把cross-build写成Release iOS或Android physical-TUN PASS。

### iOS memory

当前策略：

- 35 MiB cold-start current和45 MiB representative peak仅作优化目标。
- `TASK_VM_INFO`采样与allocator pressure relief为best effort。
- Measurement failure或越线不改变prepare/start/running/stop结果。

Release iOS无debugger整进程trace仍为`NOT RUN`。

## 6. Windows VPN

### 6.1 平台与package

已验证环境：Windows 11 ARM64 build 26200.9168，developer-signed MSIX。

Package包含：

```text
OneVCore.exe
vcore.dll
vcore-windows-vpn-host.exe
vcore-windows-session-host.exe
```

通过项：

- `Windows.Networking.Vpn` Provider activation。
- Full-trust Flutter foreground与AppContainer Provider分离。
- Hidden Session Host通过`IApplicationActivationManager`激活并取得精确PID。
- Qualified package named pipes，无product loopback exemption。
- Single package-owned VPN profile和immutable snapshot。
- Disconnected in-place upgrade和签名验证。
- Unpackaged runtime fail closed。

### 6.2 数据面

实机通过：

- IPv4/IPv6 `/1` routes。
- Windows DNS namespace。
- TCP DNS、UDP DNS/NTP、HTTP/HTTPS。
- ICMPv4/v6 local Echo。
- DIRECT、VLESS、SOCKS5、AnyTLS和同/异构proxy chain。
- Controller 401、active rates、totals、idle zero和Stop关闭。
- 非loopback socket成对绑定physical source和interface index。

2026-08-25在同一环境使用独立签名package做IPv4 route差分，配置在TUN内拒绝探针目标以阻止递归放大。对同一`223.5.5.5:53` TCP socket应用产品相同的source + `IP_UNICAST_IF`：无VPN及`0.0.0.0/1 + 128.0.0.0/1`安装前后均连接成功；VPN改成`0.0.0.0/0`后立即失败为`WSAENETUNREACH` 10051。`/0`下完全不绑定的对照取得虚拟地址`192.168.3.1`，Provider产生一个52-byte回包，证明流量进入TUN而非physical network。测试package、profile、routes和进程随后全部清理；产品package未替换。

### 6.3 Session Runtime lifecycle

通过项：

- Flutter退出后Provider、Session Host、routes、Controller和数据面继续。
- Flutter重启恢复Connected和traffic。
- Provider crash约529 ms内fail closed。
- Session Host crash约524 ms内触发Provider Stop。
- Rapid Start/Stop 20/20。
- 带TCP DNS + UDP NTP的reconnect 10/10，每轮两个native PID更换。
- 外部loopback SOCKS flow失败只影响该flow，VPN保持。
- 10分钟active pressure、110,000,000 bytes和60轮DNS/NTP。
- Provider/Session Host handles、threads和private memory无持续上升。
- Queue drop为0。

### 6.4 Bounded packet batching

Throwaway full-trust跨进程microbenchmark固定Tokio 1.52.3、current-thread runtime、64 KiB pipe buffer、1500-byte payload和现有`u16` framing。五轮各512 MiB的中位数：

| Path | MiB/s |
| --- | ---: |
| 逐frame | 262.3 |
| 2-frame | 514.1 |
| 4-frame | 624.3 |
| 8-frame | 627.4 |
| Shared-memory SPSC上界对照 | 11,011.6 |

正式实现采用8-packet bound：只等待第一包，最多drain 7个已经ready的packet，复用encoding buffer，一次写入连续v1 frames；两端reader使用64 KiB buffer。Wire protocol仍为version 1。

627.4 MiB/s是逐frame路径的2.39倍，超过500 MiB/s纯IPC目标25.5%。该结果不声明AppContainer package boundary或端到端代理达到同一数值。

### 6.5 Candidate package `26.8.1.9`

Artifact SHA-256：

```text
vcore.dll
c0c8d52024df5f37b31e0ec68f65c5a66e894ff284430b1a5e5feb181748f68c

vcore-windows-vpn-host.exe
0ab3783112acaaad3af7d4c4d30b23f14da9ef122c0555a402bb9f9b095d54a7

vcore-windows-session-host.exe
ea17bba7cb8b48fafb23224742552b21607610b9152cb729ba25534137aae7a6

OneVCore.Dev_26.8.1.9_arm64.msix
4e6ed42def9d67e4f3367c86f3e792c1eee394f55d5f1c167dcc98e38c8094aa
```

MSIX signature为Valid。用户从正式UI手动连接/断开：HTTP 200、HTTPS 204、TCP DNS和UDP NTP通过，DNS/NTP local address均为TUN地址，错误Controller secret返回401。最终Controller totals为5,995,181 / 249,227,521 bytes；Stop counters为98,617 / 194,277，三类queue drop均0。Stop后Provider、Session Host、foreground、routes、record和rendezvous全部清理。

三次50,000,000-byte外网下载为496,159 / 556,474 / 561,587 B/s；该结果受代理和网络限制，只证明持续真实数据面，不用于500 MiB/s IPC门禁。

### 6.6 Candidate package `26.8.1.10`

Artifact SHA-256：

```text
vcore.dll
c9cbefa6eb1b7d6abb5545e8e9507c5947b00c0476f8a360be0b8633722f00a3

vcore-windows-vpn-host.exe
bab6f94170d99c1027d952a42caef2a4c0b4bd9c93d820e59cc2d6e384a7a664

vcore-windows-session-host.exe
721118e86ee31f25edeb54195e96b990f6918fffcea74c7746d002b75552bde4

OneVCore.Dev_26.8.1.10_arm64.msix
b07550d00dc26db0cf7ff51e8c43d7d6b02d4008702b125b743cbd12786188e0
```

Normal non-`SkipBuild` ARM64 release build、签名和从`26.8.1.9`到`26.8.1.10`的disconnected in-place update通过，Authenticode状态为Valid。Packaged full-trust probe使用credential-free config提交外部TUN `192.168.8.1` / `fd00:8::2`及DNS `223.5.5.5` / `2400:3200::1`；interface 25精确安装两个/32、/128 client address，effective NRPT suffix `.`精确列出两个DNS address，系统`Resolve-DnsName www.baidu.com`返回A records。

相同payload重复Start保持Provider/Session Host PID `9936/1820`不变；把TUN IPv4改为`192.168.9.1`的active Start以`Windows VPN is connected with different session settings`拒绝。Stop counters为217 / 125，三类queue drop均0；随后产品process、四条`/1` routes、custom NRPT、rendezvous和session record均为0/不存在。本项没有执行Flutter UI手动验收。

## 7. 仍未完成

### Windows release

- Windows 10 22H2 build 19045。
- Native x64 Windows。
- Physical IPv6。
- WACK。
- Partner Center identity/publisher。
- Restricted capability approval。
- ARM64/x64 Store bundle和submission。
- 多用户/remote-session扩展矩阵。

### Apple / Android release

- Release iOS完整TUN lifecycle memory trace。
- Android physical-device TUN/protect矩阵。
- macOS system-extension产品矩阵。

### Protocol / operations

- AnyTLS公网service矩阵。
- 接近GeoData文件和Regex极限的性能数据。
- 长时间弱网、sleep/wake和平台升级矩阵。

## 8. 常用验证命令

```bash
cargo fmt --all -- --check
cargo test --locked --all-features --all-targets
cargo clippy --locked --all-features --lib --bins -- -D warnings -A clippy::chunks-exact-to-as-chunks -A clippy::map-or-identity
cargo test --manifest-path crates/vcore-netstack/Cargo.toml --all-targets
cargo clippy --manifest-path crates/vcore-netstack/Cargo.toml --all-targets -- -D warnings
./scripts/check_c_header.sh
```

平台build：

```bash
./scripts/build_apple.sh
./scripts/build_android.sh
powershell -File scripts/build_windows.ps1 -Architecture arm64
```

外部互操作、package、physical-device和Store结果必须在执行当次单独登记，不能仅凭这些host命令宣称通过。

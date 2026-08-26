# VCore 验收矩阵

本文只记录当前能力的验证边界，不保存候选包历史、临时进程号、一次性吞吐结果或旧产物哈希。发布产物的 revision、hash 和签名结果应写入对应发布记录。

## 证据规则

- 通过结论必须说明环境、命令、结果和适用范围。
- 主机单元测试和集成测试不能证明物理 TUN 或安装包边界。
- 交叉编译不能证明目标设备可运行。
- 模拟 IPv6 不能替代真实物理 IPv6。
- x64 模拟不能替代原生 x64 Windows。
- 外网吞吐不能替代进程间通信基准，反之亦然。
- 未执行的矩阵项保持“未验证”，不能从旧产物继承结论。
- 文档和日志不得包含 secret、凭据、UUID、密钥、完整用户配置或私有目标信息。

## 自动化覆盖

当前测试覆盖以下公共边界：

- Invoke API v5 envelope、严格 payload、单实例生命周期、panic 隔离和同步清理；
- 配置修订版 11、代理图、节点测速配置和未知字段拒绝；
- VLESS/XHTTP/TLS/REALITY、SOCKS5、AnyTLS 和代理链；
- DNS wire、缓存、singleflight、policy、故障转移和 TCP 复用；
- 规则、GeoData、HTTP/TLS/QUIC 嗅探；
- ICMPv4/ICMPv6 Echo、校验和、分片、MTU 和队列满；
- Apple/Android TUN 帧格式、文件描述符副本和关闭所有权；
- Windows 控制/数据协议、快照、会合记录、包队列、批量写入和物理网络绑定；
- Controller 鉴权、速率和累计流量语义。

常用命令：

```bash
cargo fmt --all -- --check
cargo test --locked --all-features --all-targets
cargo clippy --locked --all-features --lib --bins -- -D warnings \
  -A clippy::chunks-exact-to-as-chunks \
  -A clippy::map-or-identity
cargo test --manifest-path crates/vcore-netstack/Cargo.toml --all-targets
cargo clippy --manifest-path crates/vcore-netstack/Cargo.toml --all-targets -- -D warnings
uv run --project scripts --locked vcore-scripts check c-header
uv run --project scripts --locked vcore-scripts check tls-dependencies
uv run --project scripts --locked python -m unittest discover -s scripts/tests
uv run --project scripts --locked ruff check scripts
uv run --project scripts --locked ruff format --check scripts
```

外部互操作按需运行：

```bash
bash tests/run_xray_interop.sh
bash tests/run_anytls_interop.sh
```

## 协议与数据面

| 能力 | 自动化 | 外部进程互操作 | 物理 TUN / 安装包 |
| --- | --- | --- | --- |
| VLESS + XHTTP + TLS/REALITY | 已覆盖 | 本地 Xray harness | Windows ARM64 已覆盖 |
| SOCKS5 CONNECT / UDP ASSOCIATE | 已覆盖 | 本地 SOCKS fixture | Windows ARM64 已覆盖 |
| AnyTLS TCP / UoT v2 | 已覆盖 | 本地 harness | Windows ARM64 已覆盖 |
| DIRECT 与代理链 | 已覆盖 | 本地 fixture | Windows ARM64 已覆盖 |
| DNS / rules / GeoData / sniffer | 已覆盖 | 本地 DNS 与代理 fixture | Windows ARM64 已覆盖 |
| ICMPv4 / ICMPv6 Echo | 已覆盖 | 不适用 | Windows ARM64 已覆盖 |
| Controller 四字段流量 | 已覆盖 | HTTP fixture | Windows ARM64 已覆盖 |

“本地互操作”只证明当前双方在受控配置下可以通信，不代表所有公网服务或配置组合。

## Apple 与 Android

主机自动化覆盖：

- `utun` / `rawIp` 帧格式；
- 借用文件描述符的复制和关闭所有权；
- nonblocking 要求、EOF、非法包和部分写入；
- Android protect 回调和失败关闭；
- 重复 prepare/start/stop。

构建脚本可以生成 Apple XCFramework 和 Android arm64-v8a/x86_64 库，但构建成功不等于真机通过。

仍需独立验证：

- Release iOS 无 debugger 的完整 TUN 生命周期和整进程内存轨迹；
- Android 物理设备上的 TUN、protect、DNS、TCP/UDP 和重复启停；
- macOS system extension 的产品安装和生命周期。

## Windows VPN

已验证范围限于 Windows 11 ARM64 开发签名安装包：

- `Windows.Networking.Vpn` Provider 激活；
- 完全信任前台宿主、AppContainer Provider 和完全信任 Session Host 的进程边界；
- 同包限定命名管道和单一 package-owned profile；
- IPv4/IPv6 两条 `/1` 路由、外部 DNS assignment 和不可变 TUN/DNS 地址；
- ICMP、TCP、UDP、DNS、HTTP/HTTPS 和完整代理图；
- 非回环 socket 的物理源地址与接口索引绑定；
- Controller、外部回环 SOCKS5 和前台宿主退出后的会话延续；
- Provider/Session Host 退出、管道错误和网络变化时的失败关闭；
- 快速重连、持续压力、零队列丢弃和显式 Stop 清理；
- 断开状态下的安装包原位升级和签名校验。

Windows 路由必须保留两条 `/1`。在安装包环境中，单条 VPN `/0` 会使按产品要求绑定物理源地址和接口的外层 socket 返回 `WSAENETUNREACH`；两条 `/1` 不会产生该问题。

尚未验证或完成：

- Windows 10 20H2；
- 原生 x64 Windows；
- 真实物理 IPv6；
- 新鲜物理网卡禁用场景；
- WACK；
- Partner Center identity、publisher 和受限能力审批；
- ARM64/x64 Store bundle 与提交；
- 多用户和远程会话矩阵。

## rustls REALITY 发布

REALITY 线上向量、普通 TLS 回归、错误 key/short ID、HRR、并发和取消已有自动化覆盖。当前 `Cargo.toml` 仍通过本地 path patch 使用相邻 rustls fork，因此以下发布门禁尚未完成：

- 推送不可变 fork revision；
- 用精确 Git `rev` 替换本地 path；
- 更新并审查 `Cargo.lock`；
- 从无相邻 rustls 目录的干净检出执行 locked tests 和三平台构建。

详细要求见 [rustls REALITY 依赖与发布要求](rustls-reality-release.md)。

## 记录要求

每次正式发布单独保存：

- VCore 和 rustls revision；
- toolchain 与目标架构；
- lockfile 和产物 SHA-256；
- 签名与安装结果；
- 实际执行的物理设备、网络和失败关闭矩阵。

没有当次记录的项目不得写成发布保证。

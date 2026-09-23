# N0-B：TLS / 普通 WS / gRPC 流接口验收

日期：2026-09-23。**公共流接口可行性子门禁 PASS；N0 整体未签收。** 本轮仅新增独立 test-only workspace 和验收记录，没有接入生产 transport / YAML，没有修改第三方、主 Cargo 文件或其他仓库。Windows、真实设备和协议消费者不由本报告抵扣。

候选来源、版本、feature、许可证及上游限制见[依赖评估](N0-stream-dependencies.md)；复现入口与接口所有权见[实验 README](../../../tests/protocols/spikes/stream/README.md)。N1 公共流工作可以使用本次可行性证据；生产版本升级与平台适配仍需自身验证。

## 实现与边界

- TLS / WS / gRPC 只包装调用方传入的 `BoxStream`，不调用库内 socket / DNS / TLS URL 拨号器。真实 probe 经既有 `OutboundConnector` / `Dialer` 创建 DIRECT 或 SOCKS5 上游；每次仅一次 protect，拒绝后零 origin 连接。
- TLS 复用锁定的 rustls / 官方 tokio-rustls / ring。公开 `connect_with` 设置待发送缓冲上限，统一绝对建链期限；证书仅信任临时 fixture CA，错误名称被拒。
- WS 仅启用官方 tokio-tungstenite 的 `handshake`；显式限制读写缓冲、帧/消息和单次上传。`poll_ready` 后仅接受一次输入，flush Pending 不重复发送。空消息不被当作 EOF；Ping/Pong、text/binary 和分片有定向检查。
- gRPC 使用现有 h2 的公开流和流控接口，不新增 hyper/tonic。请求体写入与响应头读取分离，避免“服务端等首包才 flush 响应头”的死锁。发送按实际分配容量切块；接收消费后再释放窗口；gRPC 长度、tag、varint 和截断受限。
- gRPC 的唯一 H2 driver 有显式所有者，`stop().await` cancel/join 后才返回。Drop 是备用取消，不把它等同同步 Stop。读取阻塞、握手取消和建链超时均验证了真实传入 IO 的释放及对端 EOF。
- 实验限制为16 KiB上传块、64 KiB消息/记录payload、64/128 KiB H2流/连接接收窗口。它们是本轮保守预算，不是最终生产资源契约或总内存上界。未做连接池；关闭独占H2物理连接的实验不能证明共享池内其他 stream 保留。

## Mihomo 关闭行为：源码预期与实测相符

不能将 XHTTP 的关闭方式推广到所有 transport。普通 TLS/WS 的 Mihomo relay 会沿 `Upstream` 解包到 TLS/TCP `CloseWrite`；gun/gRPC 则关闭整个逻辑流。源码推导和依赖差异详见[关闭链评估](N0-stream-dependencies.md#mihomo-eof-对照必须沿包装链判断)。本轮还实际运行了官方 **Mihomo 客户端**，不是只用 Mihomo listener 证明互通。

| 模式 | VCore 实验上传 EOF | 官方 Mihomo 客户端对照（每种3次） |
| --- | --- | --- |
| TLS/TCP | `close_notify`，不调用底层 shutdown；读方向保留 | 收到完整14-byte EOF触发尾包 |
| 普通 WS/TCP | flush帧后底层写关闭，不发送WS Close | 收到完整14-byte尾包 |
| 普通 WSS | 下沉到上述TLS写关闭，保留读取 | 收到完整14-byte尾包 |
| gRPC/h2c | 逻辑流读写一起关闭，唤醒reader | 客户端EOF，无尾包 |
| gRPC/TLS | 同上；owner等待driver退出 | 客户端EOF，无尾包 |

每项在关闭前都已验证服务器先发及65,536 bytes双向回显逐字节一致；origin均及时结束。这里不承诺关闭时尚未完成的gRPC上传或未读取下行继续交付。WS early-data 的包装链不同，仍留各自门禁，不从普通WS推导。

TLS 官方 binding 的默认 shutdown 会继续关闭下层IO，与Mihomo仅发close_notify不同。本实验只用公开API发通知和flush，自有写状态拒绝后续业务写，五秒flush预算由暂停时钟测试验证；不修改rustls或tokio-rustls。

官方WS库将“帧之间正常底层EOF”和“帧中途截断”归为同类缺少Close握手错误。自有适配器仅使用14-byte头部观察状态、剩余长度和分片标记区分消息边界，数据不复制到旁路缓存，库仍负责升级校验和消息解码。只映射确认为完整消息边界的EOF；部分header、部分payload、未完成continuation和超大帧仍报错，不用吞掉所有库错误制造通过。

## 先失败与保留记录

1. TLS / WS / gRPC 各先通过公开调用边界运行未实现stub，真实失败后补最小实现。TLS默认shutdown在“不能关闭underlay”的断言失败；改用公开close_notify/flush后通过。
2. 第一轮官方互通为 **35 PASS / 7 FAIL**：普通WS/WSS两项在关闭读取阶段失败；五项SOCKS5链路被对端拒绝。原始报告保留，不改记成功。
3. WS最小回归在完整消息后底层EOF返回 `InvalidData`，确认不是传输尾包内容不匹配。加入上述边界观察后，正常与fragmented消息EOF通过，截断负例仍拒绝。
4. SOCKS5首跳与末跳最初共用一个Mihomo进程，日志明确给出 `reject loopback connection`。改为两个独立的官方进程后通过；没有关闭回环保护、修改Mihomo或绕过VCore上游。
5. 修复后的两轮完整运行均 **42/42 PASS**；最终一轮使用下述唯一产物目录。失败与成功目录分开保存。

## 本次实际执行

所有命令从VCore根目录运行。独立工作区缩写 `tests/protocols/spikes/stream/Cargo.toml`；完整命令见[README](../../../tests/protocols/spikes/stream/README.md)。

| 验证 | 结果 |
| --- | --- |
| 独立 `cargo test --locked … --all-targets` | Debug 12/12 PASS；Release 12/12 PASS |
| 独立 `cargo clippy --locked … --all-targets --no-deps -- -D warnings` | PASS；不宣称生产精简feature的既有97条warning消失 |
| 官方 `run.py` | 27 probe + 15官方客户端差分，共42/42 PASS |
| 主/独立工程fmt、harness ruff check/format | PASS |
| `cargo metadata --locked … --format-version 1` 解析图核对 | 唯一rustls0.23.43/fork既有rev、官方tokio-rustls0.26.4、ring0.17.14；h2 0.4.15；WS0.29.0仅handshake；log编译关闭 |
| 独立图排除项 | 没有Watfaq fork、第二份rustls、native-tls/OpenSSL/boring或任何AWS-LC依赖 |
| `uv run --project scripts --locked vcore-scripts check tls-dependencies` | PASS；生产SS既有局部AWS-LC例外未扩大 |
| `cargo test --locked --all-features --lib transport::xhttp::tests` | 18/18 PASS；先前生产XHTTP修复未被改变 |
| `uv run --project scripts --locked python -m unittest discover -s scripts/tests` | 42/42 PASS；测试中的模拟Windows产物不是平台构建证据 |
| `git diff --check` | PASS |

12项接口测试覆盖TLS往返/半关闭/五秒阻塞关闭、WS分片/空帧/control/正常EOF与恶意截断/活动Drop、gRPC延迟响应/分片记录/小窗口大写入/非法记录/Stop，以及三适配器的建链超时与取消。小窗口案例在128-byte HTTP/2接收窗口下传输64 KiB，不只测试四字节ping。

42项真实对端检查涵盖五模式的正常传输、关闭、SOCKS5上游、protect拒绝；适用模式追加错误SNI、path或service。失败类必须零origin连接。负例的 `driver_joined=true` 表示已有driver已经等待退出；TLS/WS没有后台driver。

### 编译与设备分别签收

以下均为独立实验的 `cargo check --locked … --lib --target <target>`，**不是完整产品构建、链接或设备运行**：

| 目标 | 本次证据 |
| --- | --- |
| aarch64-apple-darwin | 原生Debug/Release测试与probe运行PASS |
| aarch64-apple-ios / aarch64-apple-ios-sim | 交叉检查PASS |
| x86_64-apple-darwin / x86_64-apple-ios | 交叉检查PASS，不是x64原生运行 |
| aarch64-linux-android / x86_64-linux-android | NDK28.2.13676358 / API24交叉检查PASS |
| Windows ARM64/x64 | NOT RUN；本次没有原生Windows/MSVC执行环境 |
| 物理TUN、真机、打包、远端CI | NOT RUN |

## 输入与可追溯摘要

- 分支 `feat/next-protocols`；生产输入为 `8f19739d167db880d3644ed828cf17189db1efe1`，加本次独立spike。生产源码/主manifest/锁未变；提交发生在验证后。
- 宿主macOS27.0（26A428）ARM64，Rust/Cargo1.98.1、uv0.12.18。
- 主锁SHA-256 `64866bfff397559e3b5e9cb03094cfb229ccaf28ae2c8fae0a549d3a9106f8e2`；独立锁 `7827cd92626f14ed0b85c1b35c482fe6affe33327479ee33691b4e181707ffd0`；scripts锁 `25f5f660c3892e0d4b48105a4b719327fb40efced5d9ba069ad9c7fd406828c8`。
- 实验8个输入文件（Cargo.toml、Cargo.lock、run.py、src四文件、tests/streams.rs）摘要 `367b985d3a1b2f075f3d011f6c738d2ac41052c8cc6de7795f01b823d08a6ecc`。算法：实验目录相对路径字典序，对每个文件依次累加 `UTF8路径 + NUL + 原始字节` 的SHA-256；不包含文档自身。
- 每轮通过官方latest入口重新下载；实测Mihomo v1.19.31 / Go1.26.8 / with_gvisor，Darwin ARM64程序SHA-256 `fae1f37e28ee53fcf5be7a8bb121099db1fe442e44205734ed49c62579364090`。版本是本轮身份，不固定未来执行版本；hash不冒充官方签名核验。
- 单元/编译/审计日志目录 `target/interop/runs/n0-stream-20260923/`；各目标 `check-<target>.log` 保存编译结果。下面产物均相对 `target/interop/runs/`。

| 产物 | SHA-256 |
| --- | --- |
| `n0-stream-20260923T043354Z/report.json`，初轮35/7 | `12aecb085e7602dccd9d8f364f8d5b2c937dde3f670840c04349c67f3c475e48` |
| `n0-stream-20260923T044313Z-p91qeujs/report.json`，最终42项 | `a7b0d380705c74eb4c22fda616c437b89db13169a046d2eba631edd58d770545` |
| `n0-stream-20260923/tests-final.log` | `93ce170f01c7de3abb0366ed198308db26c6e199b57fd5c0e92dc18b0f5f3743` |
| `n0-stream-20260923/tests-release.log` | `1d567cb7b415e049845a752e68bc8559a790a68b1cab3113cebbc06ed6bbaff0` |
| `n0-stream-20260923/dependency-audit.json` | `1d4bb9b3dd7f97d67c8f0597a3901a93d407a5451b415cce2ed65397a548b461` |
| `n0-stream-20260923/xhttp-regression.log` | `f007709ab542ce166c85cdff73586e565420810e85884cc39e1f6724b2558a79` |

自建Mihomo进程均等待退出，临时证书与配置已删除，报告和合成peer日志保留。未改变宿主路由、DNS、VPN、防火墙或第三方代码，没有push。

## 下一步与未签收项

N1公共流接入前，单独评估h2较新patch：上游0.4.16–0.4.19包含资源、关闭和唤醒修复，当前0.4.15接口验证不能代表已获得这些修复。正式阶段冻结生产feature、错误语义、缓冲预算、TLS选项、跨层期限、driver所有权与连接池隔离，再迁移可复用实验并补消费者验收。

本轮不签收完整TLS字段、WS early-data/custom headers、生产gRPC/池、Trojan/VMess/VLESS功能、10 MiB/长测、N0-C Vision、N0-E其他高级安全、N0-F完整组合或N0-G官方WireGuard数据。Windows与其余依赖的候选/平台门禁分别保持未完成；N0整体与后续完整阶段仍未签收。

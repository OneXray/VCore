# N7.1：VLESS Encryption 开发记录

2026-09-26。**VL06 / N7.1 已完成本地子包签收；schema23 / Invoke v5。**
同一冻结输入通过公开主矩阵 59/59、另外五类公开组合 35/35、分层传输/复用
36/36，以及常规 wire 18/18、ChaCha 18/18、票据过期 9/9、最大 padding 2/2。
Apple/Android 生产 Release 构建通过；不代表完整 N7、其余高级封装组合或设备交付。
已批准官方未修改 BLAKE3 C 源与最小自有 FFI；不新增 TLS 引擎或自行实现密码算法。

## 二进制 context 原语

独立私有 crate `crates/vcore-blake3-raw` 只暴露
`derive_key(context: &[u8], material: &[u8]) -> [u8; 32]`。
官方 BLAKE3 1.8.7 C portable 源保持字节不变；来源、逐文件 SHA-256、许可证、
编译期符号前缀和 Go 向量生成器见 [crate 说明](../../../crates/vcore-blake3-raw/README.md)。
不读取外部研究路径，不在 build.rs 联网，不镜像 C 私有布局。

父提交 `65cfe35` 后执行：

- 首个固定 Go 二进制 context 向量先对占位实现失败，接入官方接口后通过。
- Debug / Release 各 3 个测试通过，包括 52 个独立 Go 向量、24 个官方 Rust
  UTF-8 接口对照和首个固定向量。含非法 UTF-8、NUL、64/1024 字节边界、
  1120/1216/17005 字节协议 context；没有使用有损字符串或替代哈希。
- 与官方 Rust `blake3` 在同一测试可执行文件链接成功；`nm` 核查 C 定义全部带
  `vcore_` 前缀，没有导出冲突的裸 `blake3_*` 符号。
- 私有 crate 的 Apple 五目标和 Android 两 ABI Release 编译通过。
  Android 首次手动命令缺少 `AR_<target>`，因找不到旧式 archiver 名称而失败；
  显式选择同一 NDK 的 `llvm-ar` 后复验通过。现有 VCore build 脚本已有该设置，
  没有修改第三方或用宿主编译器替代目标编译器。
- Clippy `-D warnings`、fmt 和 TLS dependency audit 通过。

日志：`target/interop/builds/n7-encryption-primitives-v1/`。
依赖解析使用当次官方最新稳定 `cc 1.5.1`，带入 `find-msvc-tools 0.1.14`；
现有 `blake3 1.8.7` 仅用于该 crate 的测试对照。这里尚未改变生产 VCore 依赖边。

以上只是原语与编译门禁，不是 VCore 生产平台构建、Windows 原生或设备验证，
也不是 Encryption 握手/认证、三外观×两 RTT、票据/重放、Vision 或 N7.1 互通通过。

## 原语和 wire 纵切

已复用既有 boring 公共 ML-KEM-768 / X25519 / AEAD / AES-CTR 接口。
Encryption 包装受控流，不创建 socket、系统 resolver 或每连接后台 relay 任务。
配置解析、握手/记录流、节点缓存与停止分别实现。在 wire 子包 `f83968e` 时，模块
只通过 test / interop-test 编译，公开配置仍只接受空 / none；当时 schema22 / Invoke v5。
`outbound-vless` 增加 optional 原语依赖边，不改 boring revision / TLS 后端。

独立向量由仓库内 `tests/protocols/encryption-vectors` 的 Go 生成器生成：官方
crypto/mlkem、ecdh、AES-GCM、AES-CTR，`golang.org/x/crypto 0.57.0` 的 ChaCha20-Poly1305，
`metacubex/blake3 0.1.0` 的二进制 context 派生；Go 1.27.1、x/sys 0.48.0。
没有自制协议 decoder，全部密钥为合成夹具。保留生成的 ML-KEM ciphertext 可精确
重新生成向量：

```sh
cd tests/protocols/encryption-vectors
go run . ../encryption-crypto.json
```

输出和已保存 JSON 的 SHA-256 均为
`91adec23d060906bb0f9507767458ad5eee0a2f4bf3154ee195e7674e135fb9d`。
BLAKE3 生成器的 x/sys 同步到 0.48.0 后，原 52 条向量输出仍逐字节相同。

本地 Debug / Release 各 14 项通过，包括两个 AEAD、CTR 分段、Go X25519/ML-KEM、
低阶公钥、错误 AAD/nonce/tag、解析上限/脱敏、取消读取进度、逐字节 partial write、
记录重放/截断、票据过期/代际隔离及关闭中的握手取消。测试仅使用内存 IO，未打开
宿主服务端。记录一次最多发送 8 KiB；接收先校验固定五字节头和 17..17000 密文限额，
验证 tag 后才交付明文。每节点一个票据；旧连接失败不能清除更新一代的票据，Stop
不允许在途握手重新插入缓存。握手沿用原绝对期限，等待 padding 可取消。

开发失败保留：首个 wire harness 因私有模块引用编译失败，修正自有测试导出后才
得到握手占位实现的实际 RED；1-RTT GREEN 后，0-RTT 测试曾观察到 1333 字节完整
flight 而明确失败，新增票据路径后通过。写侧 Stop 的回归先发现错误返回时未及时
释放底层 IO，修正 drain 错误路径后通过。没有修改官方对端或放宽数据断言。

## 容器 wire 门禁

`n7-encryption-wire-full-v1`：18/18 PASS，覆盖三种外观、两种 RTT 模式和三类
有序 key 链。每项四轮（IPv4/IPv6 各两轮）、双向各 10 MiB 完整校验，含 server-first。
0-RTT 通过受控 IO 的真实发送量确认短 flight；不是仅配置字符串或重复 1-RTT 成功。
独立节点执行完整握手；真实 Mihomo 对重放、未知票据、错误 key 明确拒绝，原站
零 accept。拒绝票据不自动重发业务，下一次显式连接完整握手，再下一次使用新票据。
服务端 PFS 交换、票据及长度密文三类篡改分别返回认证错误，原站零 accept。

该轮父提交 `28c6368`，CODE_PATHS 输入摘要
`fac5989c4fef773069a6d6b84a4834c8c19dc18014639704092f4d8c0b383e23`，
lock 摘要 `d18e0ac24eaa8ebc580d7d33f1ca27734886ded8edd91930582cdb2cf4ab5869`。
报告 `target/interop/runs/n7-encryption-wire-full-v1/encryption-results.json`，
SHA-256 `229563242ab9be233e48208f44b0409eb3efbc0035ab7ad56e0e94f764953b56`。
`source_unchanged=true`、`complete_selection=true`、两个所属容器全部回收。

官方 latest Mihomo v1.19.31 / Linux ARM64 / Go 1.26.8；archive
`9e0f11afbf38426b8bd88fdc594678f8161c57eccb4e1b77acb12b493904f1d4`，binary
`1b315bc038d05f84ee86d232f3c3d2b020b5044e9b971bb8fe215b6e6a2148f3`。
Apple Container host-only、MTU1500，无宿主监听或发布端口；python:3-alpine 的 digest
为 `9e9fde4d32eedce0b661d9ab91e826b62dddf28e928c230ec55f1866cac66b01`。
自有代码 Clippy `-D warnings`、Ruff、fmt 和 TLS 依赖审计通过。原语/本地日志位于
`target/interop/builds/n7-encryption-primitives-v1/`；不是设备或公开 runtime 证据。

补齐脚本入口说明后，最终完整复跑 `n7-encryption-wire-full-v2` 同样 18/18 PASS，
输入未改变、两个所属容器回收；不拼接 v1 或定向结果。其 CODE_PATHS 摘要为
`164ac2093b4f9d89fd8e36c1f8a2bdb5a667f88b8ec89f590701cde2dba61a95`，
报告 SHA-256 为 `9e3d6f4722a3dbea345dc5d81d739e54a1402f2e891c972b187c4b34f786a88f`；
父提交、lock 与对端身份同上。独立 outbound-vless feature 的 14 项也通过（11 条
未使用项警告），no-default-features check 通过（100 条警告），不称其为零警告门禁。

## 公开接线纵切（最终签收前的开发记录）

公开配置严格解析完整 Encryption 字符串；节点持有票据缓存，Stop/Drop 清理缓存。
每个受控逻辑流在外层传输建立后运行 Encryption，在 VLESS 请求之前完成接线。
WS/HTTPUpgrade/HTTP 的首发 prefix 是 Encryption flight，不先发送明文 VLESS 头。
gRPC/XHTTP 的各逻辑流分别认证；分离下载腿仍属于同一 Encryption 会话。

Vision+Encryption 仅允许 TCP / XUDP，可没有外层 TLS；不扩大到其他传输或 SMUX。
direct 切换保留外层传输，random 外观继续只变换 TLS 记录头。缓冲明文先排空，
加密 marker 先 flush；真实内层 TLS 1.3 双向直传与 TLS 1.2 不直传分别验证。
普通 Encryption 的关闭差分先发现半关闭多收尾包；改为与 Mihomo CommonConn
一致的整逻辑流关闭。Vision 真正进入 direct 后的关闭另测，不能用普通流结果代替。

以下均为增量运行，不能拼接为冻结源码下的 VL06 完整签收：

| 运行 | 实际结果与范围 |
| --- | --- |
| `n7-encryption-public-close-green-v1` | 7/7；TCP/gRPC TLS 数据及普通关闭，WS ED、Upgrade fast-open、XHTTP 下载腿 |
| `n7-encryption-vision-native-green-v1` | 3/3；无外层 TLS 的 Vision 数据/内层 TLS/普通关闭 |
| `n7-encryption-vision-random-green-v1` | 5/5；random 0-RTT 混合 key，Vision、XUDP、内外 TLS 及票据复用 |
| `n7-encryption-chacha-full-v1` | 18/18；三外观×两 RTT×三 key，强制官方 ChaCha 原语，含重放/认证负例 |
| `n7-encryption-expiry-full-v1` | 9/9；三外观×三 key，真实两秒票据过期前后完整/恢复 flight |
| `n7-encryption-padding-max-v1` | 2/2 选定项；客户端与服务端 65553 字节最大 padding |
| `n7-encryption-layers-first-v1` | 2/2；HTTP/TLS、H2/TLS；原生 V2Ray 传输 → 独立 Mihomo Encryption decoder，公开 TCP/三 UDP 编码 |

前述每次记录自己的输入 hash、官方二进制身份、`source_unchanged=true` 和容器清理。
原始报告位于 `target/interop/runs/<运行>/`，没有宿主服务器。ChaCha、过期及最大
padding 三份报告的 SHA-256 分别为
`0aa0ac641b941fd52f520118d155b8580f50d7e1ccd1b1045a1fa7a6cd1e306c`、
`f4f41c6c5115f79eea9061fd25ad4953d4cc075b5fec90e588981d68d387c36b`、
`03392984c5f08b053ee8c77ddcc2517abf041842a1e67bba498b74a1ba367b8f`。
这些测试的 CODE_PATHS 摘要为
`7e0434c95631fa2ebce2ef08e5fa45130631c996be6cbea0527d7fa55dc77e55`，
后续添加传输/关闭测试后输入已变化。

独立 Go 向量新增两种 AEAD 的 nonce 回绕/换钥和 random 头 CTR 连续性；当前 JSON
摘要 `818ca730ff28a5394b043a184cc4b43986ed450a60413152be959c49e711fffb`。
Debug/Release 各 17 个纯内存测试通过，公开配置 2 项和既有 VLESS 配置 6 项通过。
`n7-encryption-public-v1` 的 Apple 五目标/Android 两 ABI 生产 Release 构建退出 0，
不等于设备验证。随后修正五处测试代码 Clippy 写法，完整全目标 Clippy `-D warnings`
通过；后续关闭测试仍须重新运行相关门禁。

初始 public-close 运行有事件 suite 解析错误和真实 TCP 关闭差异；Vision 配置、
生产 guard 及 random direct CTR 的 RED 均保留。修正自有接线/测试，不改官方对端，
不降低完整数据或认证断言。完整六类公共矩阵、组/测速/入口、20 轮 Stop/资源、
direct 关闭、剩余传输/复用组合与最终平台构建仍待签收。

## 冻结公开矩阵及 direct 关闭

普通 Encryption 的整流关闭不能推广到 Vision direct。官方 Mihomo 客户端对照
表明：进入读或写 direct 后，native/xorpub 可沿 `Vision.Upstream()` 暴露 TCP / 外层
TLS 的写半关闭；random 的 `XorConn` 不暴露该接口，仍整流关闭。新增用例使用
真实内层 TLS 1.3、64 KiB 往返数据和 direct 计数，再比较上传 EOF 后的真实 TLS
尾包；不是普通明文 echo 或仅配置了 Vision。

`n7-encryption-direct-close-red-v1` 的三个 direct case 均实际失败：Mihomo 收到尾包，
VCore 收到空尾包。修正 Records 的 direct 关闭分支后，
`n7-encryption-direct-close-green-v1` 4/4 通过（native 1-RTT），
`n7-encryption-direct-close-random-v1` 4/4 通过（random 0-RTT）。包含普通 Encryption
关闭对照，未要求 random 提供 Mihomo 不提供的尾包。纯内存第 18 项回归独立验证
读/写 direct、两类外观、幂等 shutdown、禁止后续写以及读侧所有权。

最终公开主矩阵 `n7-encryption-public-full-v1` 使用 random / 0-RTT / 混合 key，
**59/59 PASS**。覆盖 16 种传输/下载组合各自的完整 TCP/UDP 数据与关闭，TCP-TLS
及 gRPC-TLS 的代理组、IPv6/限制、公开入口、来源隔离，以及四组各 20 轮的
同步 Stop / 资源检查；三种 Vision 外层分别验证数据、内层 TLS 1.2/1.3、XUDP、
普通关闭和真实 direct 关闭。每组均执行实际消费者，不以用例名推断行为。

- 父提交：`f83968e9595bcb8f8c0cb61695edc10b179134cc`。
- CODE_PATHS：`0d0b4b58dcadc140276bb2cfa8083b363e640951ab9d89405917f0ca9c57be10`。
- lock：`d18e0ac24eaa8ebc580d7d33f1ca27734886ded8edd91930582cdb2cf4ab5869`。
- `vless-results.json`：`56b61f9a62c099a3f3fdec6269d03c2391959fc2252c9c8185e05038f212b964`。
- `source_unchanged=true`、`cleanup=true`；所有所属容器回收，无宿主服务端。

同一生产关闭代码的 `n7-encryption-public-v2` Apple 五目标 XCFramework 和 Android
两 ABI Release 构建退出 0；不抵扣 Windows、设备、远端 CI 或发布。其余五类
外观/RTT 的定向公开验证与原生传输分层验证单独记录，不能用本矩阵替代。

同一 CODE_PATHS / 父提交 / lock 的另外五类公开验证每类 7/7，合计 **35/35 PASS**。
每类包含 TCP 数据与关闭、Vision 真实 TLS 1.2/1.3、XUDP，以及无外层 TLS / TLS /
REALITY 三种 direct 关闭差分。每份报告均记录 `source_unchanged=true`、`cleanup=true`。

| `n7-encryption-public-<profile>-v1` | `vless-results.json` SHA-256 |
| --- | --- |
| `native-1rtt-x25519` | `02bbabfa4a9082be3dc9bb08cbbed5979dd159a4f408485225493c703c96acd1` |
| `native-0rtt-mlkem` | `0ea4f6dbdfc5407e3250ac4bdee4878e162ceca1a4039d36294408ed5d76de0a` |
| `xorpub-1rtt-mixed` | `9aa2c63462c34d67c62611ac1b031c28d0e4b488b38a6c2600b1037bafd3da5c` |
| `xorpub-0rtt-x25519` | `46ccd0cf78e1bc4fe76e9de06e63292e85d575678c6ac1804ea596a853846d12` |
| `random-1rtt-mlkem` | `09cea8b38d6ba14981b4c463649ffde690f211b71cb79d02da0f1a823de7dd1b` |

冻结后的本地回归：Encryption 18、共享 security 27、配置/feature 37、共享内存传输
44 项在 Debug / Release 均通过。全 feature / 全 target Clippy `-D warnings`、
全 target 编译（`--no-run`）、fmt、Ruff、C header 与 TLS 依赖审计通过。共享传输
包含 VLESS codec/lifecycle/transports、gRPC pool、sing-mux/config、XHTTP
budget/requests/reuse；不执行含旧宿主监听器的整套运行测试。日志位于
`target/interop/builds/n7-encryption-public-v2/`，不将交叉编译表述为设备测试。

## 最终分层、wire 与子包签收

以下运行均使用上文父提交 `f83968e9`、CODE_PATHS `0d0b4b58…` 和同一 lock，
每份最终报告均 `source_unchanged=true`、`cleanup=true`。不是拼接不同源码的
增量 PASS；其中最大 padding 明确只选两项，未冒称其完整 18 项。

| 最终运行 | 实际结果 | 报告 SHA-256 |
| --- | --- | --- |
| `n7-encryption-layers-full-v1` | 36/36 | `e3687b7704b5d5c784edaf224ee6c50445ea48cf728fb813f23369a434e20ac0` |
| `n7-encryption-wire-final-v1` | 18/18，默认 padding | `a73ae4f627fa547429eae51ccb202e4c2126904275cc41283f6e4e1a1645844a` |
| `n7-encryption-chacha-final-v1` | 18/18，分段 padding | `eb97b5eba8bcc6325d269f547b1ef9f6f8f557b47b91a96a16c01e8aef76c3f5` |
| `n7-encryption-expiry-final-v1` | 9/9，真实票据过期 | `444beaa4ab6b5ae7e770a8e1f5282147a2c59c6a21570cb10a5935479a4d7501` |
| `n7-encryption-padding-final-v1` | 2/2，最大 padding | `6d1e402c17d04e34ae31d4bbd17604ea4caf6275bd56504a88438bf8020b402b` |

分层矩阵使用原生 V2Ray/Xray 终结外层传输，独立官方 Mihomo 终结 Encryption；
不使用自制协议 decoder。29 个组合覆盖 legacy HTTP/H2、WS ED header/path
的明文/TLS，XHTTP H1/H2/H3 × 三种模式，自定义 headers，H1/H3 分离下载与复用，
三种 sing-mux 的 plain/padded，以及 only-tcp；另有五个关闭和两个各 20 轮资源组。
MUX 未冒称相同包装链的 Mihomo 关闭差分，关闭用例只放在有真实对照的传输上。

两个 wire 算法矩阵逐三外观×两 RTT×三 key 链进行 IPv4/IPv6 各两轮、双向各
10 MiB 完整数据，含真实恢复 flight、重放/未知票据/错 key 和 PFS/票据/长度密文
篡改；认证负例原站零 accept。过期矩阵观测完整→恢复→过期完整→恢复，不只是
读取缓存时间。最大 padding 的 native 1-RTT/X25519 和 random 0-RTT/mixed 均对
Mihomo 配置 65,553 字节边界，客户端和服务端双方执行。

```sh
uv run --project scripts --locked python -m vcore_scripts.protocol_encryption target/interop/runs/n7-wire-fresh --padding default
uv run --project scripts --locked python -m vcore_scripts.protocol_encryption target/interop/runs/n7-chacha-fresh --chacha --padding fragmented
uv run --project scripts --locked python -m vcore_scripts.protocol_encryption target/interop/runs/n7-expiry-fresh --expiry
uv run --project scripts --locked python -m vcore_scripts.protocol_encryption target/interop/runs/n7-padding-fresh native-1rtt-x25519 random-0rtt-mixed --padding maximum
```

最终补验的独立 `outbound-vless` 18 项、no-default check 和 Python 160 项退出 0；
前两者分别有 11 / 100 项既有未使用项警告，不称零警告。全部新 peer、原站和对照
入口都在容器，纯内存测试不启宿主监听。四组公开和两组分层资源门禁共 120 轮；
不能把纯内存取消单元测试等同真实 Running Session Stop。

本次只签收 Encryption 及已实现外层传输/TCP Vision 的相应能力。它与尚未交付的
ECH、ShadowTLS、Restls、JLS 的组合归 N7.5，仍未签收；Windows 原生、真机、
远端 CI、发布和完整 N7 也不由本报告抵扣。按约定只自动本地提交。

# N7.1：VLESS Encryption 开发记录

2026-09-26。**开发中，VL06 / N7.1 未签收，公开配置仍不接受 Encryption。**
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
配置解析、握手/记录流、节点缓存与停止分别实现。模块当前只通过 test /
interop-test 编译，公开配置仍只接受空 / none；schema22 / Invoke v5 不变。
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

## 下一纵切

尚需公开 YAML / runtime / UDP、外层传输和 Vision 接线；WS/HTTPUpgrade/HTTP 的
初始 prefix 必须为加密握手，不能先发送明文 VLESS 请求头。随后补齐实际票据期限、
padding 链 / 边界、记录 nonce 换钥、原生 ChaCha 路径、Mihomo 关闭差分、公共 Stop / 资源快测及平台
构建，再做 VL06 完整签收。这里的 wire PASS 不抵扣这些未执行项目，也不等于 N7 完成。

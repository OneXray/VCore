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

## 下一纵切

复用既有 boring 公共 ML-KEM-768 / X25519 / AEAD / AES-CTR 接口。
Encryption 包装受控流，不创建 socket、系统 resolver 或每连接后台 relay 任务。
配置解析、握手/记录流、缓存与停止分别验证；WS/HTTPUpgrade/HTTP 的初始 prefix
须为加密握手，不能先发送明文 VLESS 请求头。建链沿用原绝对期限。

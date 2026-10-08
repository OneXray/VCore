# TLS 依赖与发布

版本、完整 Git revision 和 registry 校验值以 Cargo.toml/Cargo.lock 为准，
PR/发布前依据下述来源约束审查 manifest、lockfile 和 resolved graph，
不在文档复制一份易失效的包清单；编译成功不等于来源或许可证审查通过。
[Tests workflow](../.github/workflows/test.yml) 的
`Audit the locked TLS dependency graph` 步骤直接检查
`cargo metadata --locked --all-features`，维护批准的版本/revision、同源依赖、
TLS provider、ECH 算法和 SS2022/AWS-LC 消费链；没有独立的检查 CLI。

## 来源与后端

| 用途 | 来源 / 约束 |
| --- | --- |
| 普通无指纹 TLS、QUIC、共享 WebPKI | crates.io 官方 rustls/tokio-rustls，仅 ring |
| 命名 ClientHello、REALITY、JLS、ShadowTLS v3 | 自有 YuanDevTeam/boring；开发用本地路径，PR/发布用 release 分支并由 lockfile 固定完整 revision |
| SS 2022 | crates.io shadowsocks 版本依赖，原样官方库，仅 aead-cipher-2022 |
| Encryption 原语 | 同一 boring 的公共 X25519、ML-KEM、AEAD、AES-CTR；官方 blake3 |
| 静态 ECH | 官方 hpke，经 rustls 公开 HPKE trait；命名模板使用 boring 既有 ECH 接口 |

boring/tokio-boring/测试用 boring-sys 必须同源：开发时来自同一个本地 fork checkout，
PR/发布时来自同一个 release revision。PR/发布审计拒绝混合提交、未批准 revision、
其他分支及本机 path/references/rustls Git patch。
旧 rustls fork 已退役，不是回退或重建来源。分支前移不会自动改变 locked 构建。

AWS-LC 只允许 shadowsocks → shadowsocks-crypto → aws-lc-rs → aws-lc-sys 链；
不能供 TLS/REALITY 使用。禁止额外消费者、FIPS 和 2022-extra。
SS 日志抑制与未修补风险见[出站](outbounds.md#shadowsocks-2022)。

### 开发与 PR 的依赖切换

1. 本地开发将三个 crate 一起改为自有 fork checkout 的相对 `path` 依赖；保留版本和
   feature 约束，更新 Cargo.lock 后执行 locked 构建与相关测试，不混用本地和 Git 来源。
2. 发起或更新 Vole PR 前，先将所需 fork 改动发布至 YuanDevTeam/boring 的 `release`，
   再将三个 crate 一起切回 `git = "https://github.com/YuanDevTeam/boring", branch = "release"`。
   更新 Cargo.lock；若 revision 前移，对新的完整 revision 重新完成来源与能力审查。
3. 在不依赖本地 fork 的 checkout 核对三个 crate 的 Git release 来源、完整锁定
   revision、registry 校验值与 provider/feature graph，再执行相关构建和定向回归。
   同步上述 workflow 的批准身份并通过其 metadata 门禁；workflow 配置存在不等于
   CI 已运行或通过。本地 path 开发态不替代发布来源，也不放宽发布约束。

## 身份与原生接口

Vole 负责策略和受控 IO，BoringSSL 拥有握手字节、认证状态和临时秘密。
REALITY 使用同一 X25519 临时密钥生成 share、ECDH 和 session ID；连接级验证器
检查临时证书和 CertificateVerify，失败清零并终止。普通 TLS 与 REALITY 使用不同
不可变连接器，不热换身份、不保留第二个 REALITY 后端或降级开关。
模板与 ALPS 限制见[TLS 指纹](tls-client-fingerprint.md)，线格式见[REALITY](reality-wire-protocol.md)。

JLS hook 认证真正的 hello，保留 TLS 签名/Finished/记录保护；不可重试失败前清零，
非阻塞重试保留必要材料。ShadowTLS v3 复用原生 ClientHello hook 和完整 TLS1.3
认证，Vole 只包装受控 IO 的 relay 记录；未命名 cover 同样由 boring 执行。
Restls 不支持。所有 fork 补丁由 feature 控制，原始 BoringSSL 子模块不直接改写。

Encryption 的固定文本 context 使用官方 Rust blake3；二进制 context 使用
[私有薄 FFI](../crates/vole-blake3-raw/README.md)，包装未修改的官方 C portable 源，
保留逐文件 hash、许可证及符号隔离，不在构建时下载。自有临时密钥使用 zeroize，
不承诺擦除配置 String 或第三方全部内部副本。强制 ChaCha 测试入口只在 interop-test。

ECH 不引入第三套 TLS/provider；升级时审查 rustls HPKE/wire enum 接点。
Brotli/Zlib 解压采用 fork 的受限实现和纯 Rust 依赖，不新增系统 zlib。
普通 TLS 票据采用原生超时与非零 ticket hint 的较短期限；身份、票据所有权及失败策略
见[TLS 契约](tls-client-fingerprint.md)。

## 构建与发布

原生构建需要 C/C++、CMake、Perl、libclang，分别验证目标工具链。
Apple 最终链接需要 libc++（module map 已声明，直接 C 链接需 -lc++）。
Android 必须随库打包同 ABI/同 NDK 的 libc++_shared.so；只生成 libvole.so 不证明可加载。
测试用 boring-sys/foreign-types 仅服务纯内存 peer，不新增生产后端。

发布使用 Cargo.lock 固定依赖，许可证审核覆盖实际 release graph、boring MIT/Apache-2.0、
BoringSSL 随源通知及 Android C++ runtime，不能只看 crate license。

统一 [Release 工作流](../.github/workflows/release.yml) 对 CLI 与 FFI 的实际目标依赖图
执行上述审计。完整许可证与原生通知嵌入可执行程序和核心库，UWP 配套进程同样保留；
还收集实际 Rust 工具链的标准库通知，Android 同时收集随包 C++ runtime 所属 NDK
的通知。各平台在编译前收集通知，编译成功后直接打包；汇总任务收集同一次工作流生成的
归档。发布包不附带独立 license 文件。打包入口与范围见 [编译脚本](../scripts/README.md)。

## 升级与回退

1. 选择官方最新稳定依赖；fork 同步上游并先完成普通 TLS 回归。
2. 本地按上述流程验证 fork 变更；PR 前发布至 release，同次修改 manifest、lockfile
   并重新审查锁定 revision。
3. 重跑确定性向量、ClientHello/share/证书/签名、恢复/取消/期限及受影响容器数据面；
   分别验证 AnyTLS 标准 TLS 和 REALITY/JLS，不能互相抵扣。
4. 在没有相邻 fork 目录的干净 checkout 执行 locked fetch、离线测试、相关平台构建和
   原生消费者；平台编译与打包脚本不执行该消费者。
   全目标 --no-run 只是编译，网络 peer 由独立 benchmark 按[隔离规则](testing-isolation.md)执行。
5. 按[验收边界](acceptance.md)完成对应设备/安装门禁并保存当次证据。

回退使用新提交恢复仍可获取的已验证 lockfile，不恢复已退役 fork。

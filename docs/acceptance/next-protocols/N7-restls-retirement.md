# Restls 撤回，JLS 保留

2026-09-26。最终范围为**仅删除 Restls，保留 JLS**。当前 schema26 / Invoke v5；
这是一项范围收敛与定向回归，不是完整 N7 签收。

## 最终变更

- VCore 删除尚未签收的 Restls 配置、受控 IO、记录层和专项测试；主连接及
  XHTTP 下载连接的 `restls-opts` 严格拒绝，包括空对象和 null，不静默改用 TLS。
- JLS 配置、完整原生认证、主连接、下载身份替换/继承/清除、测试与文档保留。
  VCore 的 JLS 生产代码和消费者测试与本次父提交一致。
- 自有 boring fork 的已发布 `60ae6765` 曾删除两者；后续提交
  `5ca9ba3e18b59d05326d82eef926f4ec07ced8c0` 恢复 JLS，不重写已发布历史。
  Restls Rust API、Cargo feature、native patch、构建接线及专项探针仍删除。
  最终保留的生产代码、测试和探针与 JLS 基线 `a859a663` 一致。
- VCore 三个 boring crate 统一固定到上述最终公开 revision。Cargo.lock 相对父
  提交只变化三条 Git source；官方 rustls、ring、Windows 配套解析均未变化。
- 字段目录 schema-v2 移除 S09–S11 / D22–D24 与 VL-RESTLS 家族，保留 JLS 的
  S12–S13 / D25–D26；其余 ID 不重排，当前为 139 字段 / 68 组合家族。
- [原 Restls 契约](retired-restls-contract.md)、[开发失败](N7-restls.md)和
  [gRPC EOF 诊断](N7-restls-grpc-diagnosis.md)作为历史保留，不再是 N7 门槛。
  未保留此前尝试的 gRPC 启动合并候选或临时诊断 hook。

共享夹具仅保留两项改进：容器内 cover 最多八路并行，避免独立下载腿被前一
握手阻塞；在清理前读取容器日志快照，避免实时日志缓冲遗漏。未修改 Mihomo。

## 冻结输入

测试发生在 VCore 提交前，不能倒填新提交为测试时的父提交。下面的源码身份
覆盖 Cargo.toml、Cargo.lock、src、crates、tests、scripts、include；不包含文档。
全部检查结束后再次核对内容 hash 一致。

| 项目 | SHA / SHA-256 |
| --- | --- |
| VCore 父提交 | `9ec0d5ab96f2916588e8d1dcc7f6dce1ed97c083` |
| CODE_PATHS 内容 | `bea2e91d2ab9b4b1a0bda3ab578cb1b194d1d61b4db4b4ae98911408a2ba2f2c` |
| 运行时 dirty patch | `c70333c7e78f5d38dedd6b294c0ee68265b44c0abe81ab1d04a6747675e26592` |
| Cargo.lock | `6a9c09b57c0461d8be8a3bd26d811be534ff664cd95b6b6eaa14aae730da9384` |
| 容器报告 | `68b5564b0b86b0f48190f1b64d62a501f93b8c0f014d055a186883e566cf6769` |

boring 远端分支 `chore/remove-jls-restls` 已核对最终完整 revision；分支名来自
最初范围，不表示 JLS 仍被删除。BoringSSL 子模块和保留补丁 hash 未变化，见
[TLS 依赖](../../tls-dependencies.md)。fork 本地 Debug 51 项、Release 35 项及
所选库/测试 Clippy 通过；这是独立库的内存 IO 证据，不替代以下 VCore 消费者。

## 本地回归

环境：macOS ARM64、Rust 1.98.1。无网络测试使用内存 IO，不启动宿主服务端。

| 检查 | 本次结果 |
| --- | --- |
| Debug：retired_security / n7_jls_config / feature_foundations / grpc_pool | 2 + 10 + 6 + 2 PASS |
| Debug：config 单元测试 / security 单元测试 | 76 + 27 PASS |
| Release：上述四个集成测试文件 | 20 PASS |
| 全 feature / 全 target `--no-run` | 编译 PASS，不计为执行全部测试 |
| 无默认 feature 库检查 | PASS，100 项既有未使用项警告，不称零警告门槛 |
| 全 feature 库和二进制 Clippy `-D warnings` | PASS |
| Python unittest / Ruff check / Ruff format | 162 PASS / PASS / 85 文件 PASS |
| TLS 依赖审计 / C header / rustfmt / diff-check | PASS |
| 协议目录校验 | 139 / 68，`VALID / NOT RUN`，不是行为通过 |

新增拒绝测试同时验证普通 TLS 和 JLS 正例，以及旧 Restls 字段的普通值、
空对象、null、错误类型；错误不得回显凭据标记。依赖审计要求 JLS feature，
拒绝三个 native crate 中任一个重新启用 Restls。

```sh
cargo test --locked --all-features --test retired_security --test n7_jls_config --test feature_foundations --test grpc_pool
cargo test --locked --all-features --lib config::
cargo test --locked --all-features --lib security::
cargo test --locked --release --all-features --test retired_security --test n7_jls_config --test feature_foundations --test grpc_pool
cargo test --locked --all-features --all-targets --no-run
cargo check --locked --no-default-features --lib
cargo clippy --locked --all-features --lib --bins -- -D warnings
uv run --project scripts --locked vcore-scripts check tls-dependencies
uv run --project scripts --locked vcore-scripts check c-header
uv run --project scripts --locked vcore-scripts check protocol-coverage --catalog-only
uv run --project scripts --locked python -m unittest discover -s scripts/tests
uv run --project scripts --locked ruff check scripts
uv run --project scripts --locked ruff format --check scripts
cargo fmt --all -- --check
git diff --check
```

## 隔离 Mihomo 定向回归

报告位于 `target/interop/runs/n7-restls-removal-jls-retained-v1/vless-results.json`。
同一冻结输入 **10/10 PASS**，`source_unchanged=true`、`cleanup=true`，
13/13 个所属容器回收。Apple Container host-only、guest MTU 1500，所有服务端、
业务原站和参考客户端 listener 均在隔离容器中，无宿主服务端。

每次由 official latest 链接重新下载，不使用本地 Mihomo 源码或缓存回退。
实际版本 `Mihomo Meta v1.19.31 linux arm64 / go1.26.8 / with_gvisor`；下载包
SHA-256 `9e0f11afbf38426b8bd88fdc594678f8161c57eccb4e1b77acb12b493904f1d4`，
二进制 SHA-256 `1b315bc038d05f84ee86d232f3c3d2b020b5044e9b971bb8fe215b6e6a2148f3`。

```sh
uv run --project scripts --locked python -m vcore_scripts.protocol_jls \
  target/interop/runs/n7-restls-removal-jls-retained-v1 \
  N7-JLS-TCP-BASE N7-JLS-TCP-AUTH \
  N7-JLS-GRPC-BASE N7-JLS-GRPC-CLOSE \
  N7-JLS-XHTTP-STREAM-UP-DOWNLOAD-BASE \
  N7-JLS-XHTTP-STREAM-UP-DOWNLOAD-AUTH \
  N7-JLS-XHTTP-STREAM-UP-DOWNLOAD-IDENTITY \
  N7-JLS-XHTTP-STREAM-UP-DOWNLOAD-H1-BASE \
  N7-JLS-XHTTP-STREAM-UP-DOWNLOAD-H1-AUTH \
  N7-JLS-XHTTP-STREAM-UP-DOWNLOAD-H1-IDENTITY
```

重跑须换新的输出目录。覆盖 TCP、gRPC、XHTTP H1/H2 独立下载连接的数据面、
认证失败和独立身份。gRPC CLOSE 沿用明确标记的 Mihomo Chrome 指纹关闭参照，
待测 VCore 仍无指纹；原因见 [JLS 原始记录](N7-jls.md)，不称完全同配置差分。
本轮不替代原 JLS 全部 122 项矩阵，不将历史 PASS 冒充本次执行。

## 生产构建

Xcode 27.0（27A266a）、Android NDK 30.0.16248370 / API 24，生产 feature 集合，
不含 `interop-test`。iOS ARM64 Release 静态库和 Android ARM64 Release 动态库
通过，产物均核对 Invoke v5 / config26 身份；Android 同时复制匹配的 C++ runtime。

首次 Android 命令遗漏显式 bindgen API target，报
`Unversioned target triples are not supported!`。按既有验收命令补上该环境参数后
重跑通过；没有修改源码或第三方依赖，不把初次失败追改为 PASS。

```sh
IPHONEOS_DEPLOYMENT_TARGET=13.0 CARGO_PROFILE_RELEASE_PANIC=unwind \
  cargo build --locked --release --target aarch64-apple-ios --no-default-features \
  --features ffi,tun,inbound-http,inbound-socks5,outbound-anytls,outbound-socks5,outbound-shadowsocks,outbound-trojan,outbound-vmess,outbound-vless,outbound-hysteria2 --lib
VCORE_ANDROID_NDK_VERSION=30.0.16248370 \
  BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android=--target=aarch64-linux-android24 \
  VCORE_ANDROID_TARGETS=aarch64-linux-android \
  VCORE_ANDROID_OUTPUT_DIR=target/interop/builds/n7-restls-removal/android \
  uv run --project scripts --locked vcore-scripts build android
```

| 产物 | SHA-256 |
| --- | --- |
| `target/aarch64-apple-ios/release/libvcore.a` | `5a130a633b3728de76a02fc595722254aee039838c85fd8b045f9ad50b78802f` |
| `target/interop/builds/n7-restls-removal/android/arm64-v8a/libvcore.so` | `ed71c6187d6d750a79d77fb5321081134a7b2c1ebc81b05135235ca1b9a764bf` |
| 同目录 `libc++_shared.so` | `7466ed097631a564ed6bff0b47768caa76bf03270d2047b5a65c03f497b824df` |

本轮未执行 Apple 五目标/XCFramework、Android x86_64、Windows 原生、设备/TUN、
远端 CI 或完整发布验收。N7.3 ECH、N7.4 ShadowTLS 与 N7.5 组合仍按各自计划，
JLS 已有签收继续保留，Restls 不再阻塞；不进入 N8、不宣称完整 N7 完成。

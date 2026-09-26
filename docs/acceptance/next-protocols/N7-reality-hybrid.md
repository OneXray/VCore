# N7.2：显式混合 REALITY

2026-09-26。**N7.2 完成本地子包签收：生产互通 54/54、共享容器回归 32/32、Apple 五目标与 Android 两 ABI Release 构建 PASS。N7 整体未完成。**
本报告只覆盖 S03 / D16，不抵扣 Encryption、ECH、附加封装或 N7.5 汇合验收。
原始失败和后续授权见 [N7 进度](N7-progress.md)。

## 配置与实现边界

- schema22 / Invoke API v5。`reality-opts.support-x25519mlkem768` 是严格非 null bool，
  默认 false；既有经典模式不变。主腿和独立下载腿分别校验。
- true 只接受无命名指纹或 `chrome`（Chrome133）。其他已支持模板在 IO 前拒绝，
  不把 Chrome120 / Firefox / Safari 静默改成另一套模板。
- 无命名指纹的实际 share 为 `(4588,1216)`；Chrome133 为 `(4588,1216),(29,32)`。
  只有实际协商 group 4588 才成功；经典选择、HRR 或无共同组明确失败，不重试经典模式。
- 下载 `reality-opts` 缺省继承整个对象，`{}` 清除；非空替换必须给 public-key，
  short-id 默认空、混合开关默认 false，不按叶合并。H3 仍只能使用普通 TLS。
- 复用原受控 Dialer / 上游图 / 原建链期限 / 同步 Stop。REALITY 认证仍是
  X25519 / Ed25519，不宣称后量子身份认证。
- boring / boring-sys / tokio-boring 锁定已获准发布的
  `b7639ab705076748133d5e8658914e3c3a364cb6`，官方 rustls 0.23.45 / ring 不变。
  Cargo.lock 仅改三条 Git source，未变更 Windows 配套依赖。

## 冻结输入与真实对端

完整运行：`target/interop/runs/n7-hybrid-vcore-full-v3/reality-results.json`。

| 输入 | SHA-256 / revision |
| --- | --- |
| 测试时父提交 | `2edd7759939f8a07733ac39f62d29b018722e97c` |
| 所有 CODE_PATHS 文件内容 | `1cfe7216096efb14497a1c04c5bcdbc157b1726ff39204a63659c2b0a5064058` |
| Git tracked patch | `107261ad358377989feb0d13edfc2b76eafde87d619ffed069397af9ffdece7d` |
| Cargo.lock | `8a75c4e68c4c5e461b9b059666c2029d361111d43cce3b877a89e0b7d52e6a1c` |
| 完整结果 JSON | `cf0bdfbe8b5a7cad1677d36f88bdee03a5bd6c34141ab48ea6f6515bb1c11e23` |
| Mihomo 官方 archive | `9e0f11afbf38426b8bd88fdc594678f8161c57eccb4e1b77acb12b493904f1d4` |
| Mihomo 实际 binary | `1b315bc038d05f84ee86d232f3c3d2b020b5044e9b971bb8fe215b6e6a2148f3` |

`source_identity` 的 CODE_PATHS 包含 Cargo 清单/lock、src、crates、tests、scripts、
include 的 tracked 与 non-ignored untracked 文件；文档收尾不影响该源码摘要。
不把提交后才存在的 SHA 倒填为被测父提交。结果 `complete_selection=true`、
`source_unchanged=true`、`cleanup=true`，54 个 case 均有结构化断言和 wire hash。

对端为当次从官方 latest 获取的 Mihomo v1.19.31 / Linux ARM64 / Go 1.26.8，
cover 使用 OpenSSL 3.5.8；Apple Container host-only 网络、guest MTU 1500。
四个独立容器分别运行 origin、cover/观察器、Mihomo listener、Mihomo 上游；
全部回收，无宿主服务端或发布端口。镜像 `python:3-alpine` digest：
`sha256:9e9fde4d32eedce0b661d9ab91e826b62dddf28e928c230ec55f1866cac66b01`。
观察器只保留组号、长度、原生拒绝原因和关闭元数据，不保存原始握手或秘密。
XHTTP 两个观察入口转发到同一个 Mihomo handler，不能用两个独立 handler 假装下载腿成功。

## 完整 54 项子门禁

```sh
uv run --project scripts --locked vcore-scripts check reality-hybrid \
  --run-dir target/interop/runs/n7-hybrid-vcore-full-v3
```

重跑须改用不存在的新 run-dir，不覆盖原始记录。

| 类别 | 实际通过 |
| --- | --- |
| 两种指纹 × TCP / WS / HTTPUpgrade / fast-open / gRPC / Vision / H1、H2 各三种 XHTTP mode | 24 |
| 两种指纹 × H1/H2 × 主腿 classic / 下载腿 classic（另一腿 hybrid） | 8 |
| 两种指纹 × TCP/H1/H2 的错误身份及经典/HRR/普通证书/TLS1.2 拒绝 | 6 |
| 两种指纹 × Vision 内层 TLS 数据 | 2 |
| 两种指纹 × 上游图/切组、IPv6/保护拒绝、HTTP/SOCKS5/合成 TUN 入口 | 6 |
| Chrome TCP/gRPC/Vision/H2 stream-up × 公共生命周期/自有资源 | 8 |

最后八组各 20 轮，共 160 轮。Stop 返回立即检查归零，再静默观察五秒；
资源快照涵盖 task、socket、session、association、reassembly、pool、waiter、handshake。
认证负例要求明确错误而非 timeout，并验证业务原站零连接/数据。

无命名指纹只声明混合组，因此不兼容 cover 的真实结果是原生
`NO_SUITABLE_KEY_SHARE` 和零字节 ServerHello flight；Chrome133 可收到经典
group 29 或 group 24 HRR。门禁分别验证真实形态并逐腿计数，不将缺失观测当成功。

## 共享容器回归

`chrome`、`chrome120`、`firefox`、`safari` 各 8/8，合计 32/32 PASS。
每套均检查 AnyTLS、Trojan TCP、VMess gRPC、VLESS 普通 TLS，以及经典 REALITY
TCP/gRPC/Vision 与错误认证；未启用新混合开关。四次运行的源码摘要与完整子包一致，
`source_unchanged=true`、`cleanup=true`；每次 21 个、共 84 个所属容器回收。
这是受影响路径的定向回归，不冒称重新执行全部 CF5 的 228 项。

```sh
for profile in chrome chrome120 firefox safari; do
  uv run --project scripts --locked python -m vcore_scripts.protocol_fingerprint \
    --client-fingerprint "$profile" "target/interop/runs/n7-hybrid-regression-${profile}-v1" \
    F5-ANYTLS N4-REGRESSION-TROJAN-TCP N4-REGRESSION-VMESS-GRPC N4-TCP-TLS-BASE \
    N4-TCP-REALITY-BASE N4-GRPC-REALITY-BASE N4-VISION-REALITY-BASE N4-TCP-REALITY-NEG || exit
done
```

各目录 `vless-results.json` 的 SHA-256：

| profile | SHA-256 |
| --- | --- |
| chrome | `de2f75b4702fe3bfc1d54d5c333e0e68105dba30acfbe7020b822a53b62f5706` |
| chrome120 | `c6a2fa3114001b02bc391c563589ca427af9fc2842542ddca368a3b745ff8180` |
| firefox | `9a3e77bd6f0f5d6f31af2f99c2bdb2f466f3003a72d5aade9dc30f2ae560f385` |
| safari | `36a180b1107799dfccb875e6e57df5f815084d5ea926f394621831dce5500b82` |

## 当前本地检查

- Debug：`n7_reality_config` 7、`n7_security_capabilities` 5、`vless_config` 6、
  `xhttp_config` 11、`feature_foundations` 6，合计 35 PASS。
- 全 feature 的纯配置单元测试 76 PASS、纯内存 security 单元测试 27 PASS；
  独立下载 fixture 的无网络回归 1 PASS。
- Clippy `--lib --bins --test n7_reality_config --test n7_security_capabilities
  --test vless_native --test vless_public -- -D warnings`、fmt、diff-check 通过。
- Python unittest 160 PASS，Ruff check/format、TLS dependency audit、C header 检查通过。
- Release：同一组公开配置测试 35 PASS、配置单元测试 76 PASS、security 单元测试 27 PASS。
- 仅 `outbound-vless`：18 PASS；无 default feature：6 PASS；默认 `cargo check` 通过。
  三种精简构建分别有 112、100、126 项未使用项警告，不称零警告验收。
- `cargo test --locked --all-features --all-targets --no-run` 编译通过；未执行其中的旧宿主 listener 测试。

## 生产平台构建

执行环境为 Rust 1.98.1、Xcode 27.0（27A266a）/ SDK 27、官方 Android NDK
30.0.16248370。构建均使用现有生产 feature 集合，不含 `interop-test`。
命令和本地测试日志保留于 `target/interop/builds/n7-hybrid-v1/`。

```sh
VCORE_APPLE_DIST_DIR=target/interop/builds/n7-hybrid-v1/apple \
  uv run --project scripts --locked vcore-scripts build apple
ANDROID_NDK_HOME=/Users/yiguo/Library/Android/sdk/ndk/30.0.16248370 \
  BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android=--target=aarch64-linux-android24 \
  BINDGEN_EXTRA_CLANG_ARGS_x86_64_linux_android=--target=x86_64-linux-android24 \
  VCORE_ANDROID_OUTPUT_DIR=target/interop/builds/n7-hybrid-v1/android \
  uv run --project scripts --locked vcore-scripts build android
```

Apple 的 aarch64 iOS、aarch64/x86_64 iOS Simulator、aarch64/x86_64 macOS
五个 Release 目标及 XCFramework 打包通过。Android 两 ABI 通过，并包含同一 NDK
的 `libc++_shared.so`；使用既有自有 CMake toolchain 和显式 bindgen API target。

产物相对于上述输出目录的 SHA-256：

| 产物 | SHA-256 |
| --- | --- |
| apple/LibVCore.xcframework/ios-arm64/libvcore.a | `30f584b33bc19c93ca9942cb86fca2dcca669e82e4024d4f8bee20c1ef7cbc88` |
| apple/LibVCore.xcframework/ios-arm64_x86_64-simulator/libvcore.a | `aea06600a0f12a5d0b3d476ef41933fa82cbbd4224c5bf9b9ecf156a4bd78617` |
| apple/LibVCore.xcframework/macos-arm64_x86_64/libvcore.a | `bd2e6814f0ca4f359be76df8c7a238c52195f1b559bc16f91e87cb114b57d546` |
| android/arm64-v8a/libvcore.so | `e782c5982c6034caad5d2c2470fd1e563142183814261bba6f22a881219d5493` |
| android/arm64-v8a/libc++_shared.so | `7466ed097631a564ed6bff0b47768caa76bf03270d2047b5a65c03f497b824df` |
| android/x86_64/libvcore.so | `faaf23c3ac70b6d41130842cb2423cce6a1c443603ea33b4dab5f9f527906255` |
| android/x86_64/libc++_shared.so | `7918ebd0b8074c312d0c610205d49760b98c008026e6b817cd92103a3e12241b` |

未执行旧宿主 listener 的全量 Rust 测试；不以编译、内存测试、合成 TUN 或容器结果
代替 C/Swift 最终消费者链接、Windows 原生、Apple/Android 真机、系统 VPN、远端 CI 或发布签收。

## 保留的失败

smoke-v1 是测试错误类型转换的编译失败；full-v1 主动中断；full-v2 的无模板
拒绝观测谓词有误；security-v2 的 native fixture 未准备独立下载端点。
各失败/中断均保留原记录和清理结果，不改记 PASS。定位、先红后绿修复及定向
security-v3 的 6/6 复验见 [开发记录](N7-progress.md)；最终完整 v3 独立通过，
没有从前几轮拼接通过结果，也没有放宽生产认证或修改第三方服务端。

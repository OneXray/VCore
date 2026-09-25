# selected-v1 CF5：独立 checkout 与平台构建

2026-09-25，本地构建 / 打包 / 链接通过，**不代表设备或发布验收**。
本记录属于 [CF5](CF5.md)，构建证据与传输矩阵分别记录。

## 来源与独立性

- VCore 父提交 `1cbd4c771faab87b0eb3c40148d191d9965ff0ea`；由暂存树
  `318bf885435b630f20db6bcbcb6ade4a37f8ef1e` 使用 `git checkout-index` 导出。
- 导出时受验代码树 SHA-256：
  `ffbf6284d351bf6b02cdd27b825a5b5122d9c5ed47d33e4c95eb507cc5e926e0`；
  Cargo.lock：`7f30266603963a3e4c65dc5d4be9e2ce439be5aeea4779e693e5f64bed27b482`。
- 使用公开可获取的 boring / boring-sys / tokio-boring revision
  `67581195fd6388a8bfd42c4e39e945f73c99a2b2`；不使用 path 替换。
- 临时导出目录不含 `.git`，也不存在相邻 boring / rustls / references。
  `cargo fetch --locked` 成功，随后使用新 target 目录进行 `--locked --offline`
  构建成功。复用了全局 Cargo 下载缓存，**不宣称空缓存下载**。
- 调试构建 feature 为 `ffi,tun,inbound-http,inbound-socks5,outbound-anytls,`
  `outbound-socks5,outbound-shadowsocks,outbound-trojan,outbound-vmess,outbound-vless`，
  配合 `--no-default-features`，没有打开 interop-test。

后续补充的下载腿内存测试、容器网关夹具、报告校验及文档不改变上述生产实现或依赖。
新增 Rust 子模块仅在 `cfg(test)` 下编译；这些后续测试不能说成已在导出快照中执行。

## 平台结果

从上述独立导出目录执行仓库现有 `vcore-scripts build apple` / `build android`，
`CARGO_BUILD_JOBS=2`，仅以 `VCORE_APPLE_DIST_DIR` / `VCORE_ANDROID_OUTPUT_DIR`
指定忽略的产物位置。原始 `fetch.log`、`build.log`、`apple.log`、`android.log`
同时保存在下述产物目录的 `logs/` 中。

| 目标 | Release / 打包 | 最终链接与运行边界 |
| --- | --- | --- |
| iOS arm64 | PASS，XCFramework device slice | C 最终可执行文件链接 PASS；未签名、未上设备 |
| iOS Simulator arm64 / x86_64 | PASS，universal simulator slice | 两架构 C 最终链接 PASS；未启动模拟器 |
| macOS arm64 / x86_64 | PASS，universal macOS slice | 两架构 C 最终链接 PASS；arm64 C / Swift 各运行 1,000 次 Invoke/Free PASS；x86_64 未运行 |
| Android arm64-v8a / x86_64 | PASS，两份 libvcore.so 与 libc++_shared.so | API 24 C 最终 ELF 链接 PASS；未在 Android 运行 |

Apple C 消费者显式链接 Security / SystemConfiguration / CoreFoundation、resolv、iconv
及 libc++；Swift 消费者经公开 module map 导入 `LibVCore`，验证自动导入 C++ 链接依赖。
运行检查使用真实 C ABI 获取 schema 20 版本响应并释放返回内存。

Android 使用已安装 NDK `28.2.13676358`。`llvm-readelf` 检查 ELF 架构及动态依赖，
两架构均仅依赖 `libc++_shared.so`、`libdl.so`、`libc.so`。最终链接使用
`--no-allow-shlib-undefined`，同 ABI 的 companion 与该 NDK sysroot 文件逐字节一致。
这些检查不能推导 Android 安装、JNI 调用或设备网络行为通过。

## 产物身份

产物位于忽略的 `target/interop/builds/selected-cf5-20260925/`，不提交二进制。

| 产物 | SHA-256 |
| --- | --- |
| Apple device libvcore.a | `b421a49db60fb4178efafdcc57a26d9052538f739938599b817c3a310ee96bb7` |
| Apple simulator universal libvcore.a | `b75693b3145b0b6d6cd4d6f9b8332d7d768be3bf2fe430278655cbb4da2082c0` |
| macOS universal libvcore.a | `fcedcc98ee98d9c3cd56ebf8f51f87a1b3d306953461f1a8ddec5954e1844852` |
| Android arm64 libvcore.so | `5bac35ddb1a33425479623c162600052b2ebee8144021a50cc937dce538e265f` |
| Android x86_64 libvcore.so | `40c3a19d001c27ee49c0b9941277d89ffe9067b9add7bf4392c1d3e62d8b2ca1` |
| Android arm64 libc++_shared.so | `ab4e6c71b96b851de45a8a9bd86369e7dbc2130a44b3b4520564be94847910f2` |
| Android x86_64 libc++_shared.so | `e4cd73c8a3607269f3be58d15c21f78bff112e27f9398d6261e5f965668f8746` |

## 收尾锁文件校正

完整矩阵结束后，恢复更新 fork 时无关改动的五条 Windows 依赖选择：errno、quinn-udp、
rustix、socket2、tempfile 的 windows-sys 均回到父提交的 0.61.2，未添加新版本或新包。
这五条上游依赖均受 `cfg(windows)` 限制。最终锁文件 SHA-256 为
`45cc8ac15f7c15c68ce336cac77cc7da7f7d0ccdccfea5e00647b1b0b69874b1`。

对 Apple 五目标、Android 两 ABI 分别执行以下命令，保存校正前后输出并逐字节 `cmp`，
七组均完全一致；因此上述平台产物和本机协议代码的实际依赖未变。不把原始产物重标成
由新 lockfile 构建，也不改写原互通报告的受验摘要。

```sh
cargo tree --locked --offline --all-features --target <target> -e normal,build,dev,features
```

证据目录为 `target/interop/runs/selected-cf5-lock-audit-20260925/`，另保存
`aarch64-pc-windows-msvc` 的 locked 解析结果；后者只是解析通过，不是 Windows 编译。
最终锁文件重新通过宿主全目标编译、Clippy、安全/配置/下载腿测试、结构/恢复检查及
依赖审计，详见 CF5 主记录。

Windows 原生构建、远端 CI、物理设备/TUN、性能/体积与完整发布许可证检查均 NOT RUN。

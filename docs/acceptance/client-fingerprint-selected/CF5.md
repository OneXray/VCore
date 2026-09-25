# selected-v1 CF5：完整本地回归

2026-09-25 UTC（本地收尾为 2026-09-26）。父提交 `1cbd4c7`，**本地 DONE**。
VCore 未 push；fork 后续只读接口提交 `67581195fd6388a8bfd42c4e39e945f73c99a2b2`
已在获准的同一功能分支发布并锁定。不继承旧 CF4 / N5 / 平台成绩。
四模板 228/228 项独立容器检查通过，520/520 个所属容器回收；本地必需项无剩余
FAIL / BLOCKED / NOT RUN。Windows 原生、物理设备、远端 CI 与发布仍是独立门禁。

## 结构与恢复检查发现的修正

1. REALITY 调用方原先将 builder 的 minimum version 设为 TLS1.3，导致原生编码删掉
   模板的旧 cipher/扩展。最小 Firefox REALITY 比较得到参考 17 项、实际 3 项。
   只将命名 REALITY 的 offer 下限恢复为 TLS1.2；原生 REALITY 自身在 ServerHello 阶段
   拒绝 TLS1.2，默认 `none` 仍发 TLS1.3-only offer。修正后完整参考结构一致，四模板
   的受控 TLS1.2 对端均收到 protocol_version 拒绝；普通 TLS 对照成功。
2. 两秒 TLS1.2 票据在三秒后仍恢复。原生源码分别保存 session timeout 与 ticket hint，
   VCore 原先只检查前者。fork 暴露既有只读 getter，不修改 BoringSSL；缓存取非零较短
   期限。44 项 fork 库测试及 focused Clippy 通过。Safari TLS1.2 无 ticket 扩展，使用
   session ID，因此单独记录其仍有效的状态，不伪造“票据过期”成绩。
3. 首轮 H2 上传/H3 下载的夹具向 Xray 配置 `[h2,h3]`，但官方 Xray `26.3.27`
   仅在 ALPN 恰为 `[h3]` 时启用 QUIC，该配置实际只启动 TCP。11 秒业务读取超时，
   首轮保留 FAIL。改用已批准的官方 latest xcaddy/Caddy 构建：同时终结 H2/H3 与
   mTLS，转发同一个原生 Xray h2c handler，再用 Mihomo 解码，不修改第三方代码或
   VCore 传输实现。修正后的独立用例通过完整双向 TCP/UDP 与 mTLS 验证，随后四模板
   完整矩阵重新执行并全部通过。该路径不宣称原生 Xray 同时监听 TCP/QUIC。
4. 首轮汇总把 Git patch 摘要也当作不可变输入；暂存原已捕获的未跟踪测试文件后，
   patch 摘要变化，完整路径/内容树摘要未变。两个子报告均 `source_unchanged=true`，
   汇总误报 false。比较改为完整内容树、父提交与 lockfile；继续保存 patch 摘要，
   不忽略真实源文件变化，新增离线回归覆盖这一区别。

所有首次失败保留在执行过程与原始捕获中；比较器没有以删除 cipher/PSK 字段掩盖失败。
普通 Vision/XHTTP 的 TLS1.3-only 策略差异逐字段列入当前契约，REALITY 不继承该裁剪。

## 本地验收结果

- 初次 `selected-cf5-wire-20260925-1235/shape-results.json`，以及完整容器矩阵同一输入上的
  `selected-cf5-wire-final-20260925/shape-results.json`，及收尾锁文件上的
  `selected-cf5-wire-lock-final-20260925/shape-results.json`：168 组公开配置冷/后续未认证
  ClientHello 与独立 CF0 样本比较通过；24 组独立 rustls 内存对端的冷/实际恢复/期限
  检查通过。涵盖六名称、四模板、短/长 SNI、TCP/WS/gRPC/REALITY/Vision/XHTTP H1/H2。
  票据长度由独立对端实际签发长度核对；PSK/binder 宽度、位置及恢复成功单独验证。
- security 内存测试 27 项、配置 75 项、脚本离线测试 150 项、全目标/全 feature
  Clippy、全目标 `--no-run`、fmt/Ruff 通过。`--no-run` 仅编译，不执行历史宿主
  服务端测试。所有网络服务端仍必须在容器，内存测试不打开宿主监听器。
- `selected-cf5-20260925-1240-chrome/`：46 项传输 PASS，XHTTP 前 10 项 PASS，
  最后 H3 混合下载项 FAIL；所有容器已清理，完整源树摘要不变。该失败报告不追改。
- 两条生产 XHTTP 工厂的下载腿内存隔离测试通过：四模板 × 继承/异模板/关闭 × 两工厂，
  24 个节点配置，实际握手、票据恢复与 mTLS 交叉拒绝；无宿主网络监听。
- 全 feature 的 feature-foundations 6 项通过；仅 inbound-socks5，以及分别增加
  AnyTLS/Trojan/VMess/VLESS 的五种精简组合各 6 项通过。精简组合保留历史 unused/dead-code
  警告，不将编译成功描述为这些组合的零警告 Clippy。C header 与当前 TLS 依赖审计通过。
- `selected-cf5-h3-gateway-20260925/xhttp-fields-results.json`：修正夹具后，Chrome133
  的 H2/H3 下载清除用例 PASS，cleanup/source_unchanged 均为 true。
- `selected-cf5-final-20260925-{chrome,chrome120,firefox,safari}/`：四模板各 46 项
  传输 + 11 项 XHTTP 补充，合计 228/228 PASS。八个子报告的 cleanup/source_unchanged
  均为 true；各模板 106 + 24 个容器全部 joined，合计 520 个。
- Apple 五目标及 Android 两 ABI 的生产 Release 构建、打包和最终 C 链接通过；
  macOS arm64 的 C / Swift 各 1,000 次 Invoke/Free 调用通过。
  [独立构建记录](CF5-builds.md)保留来源、命令、哈希与未执行边界。
- Windows 原生、物理设备/TUN、远端 CI、性能/体积和完整发布许可证检查 NOT RUN；
  不把平台构建或容器网络成绩称为全平台发布完成。

## 完整容器矩阵身份

每个目录的 `fingerprint-results.json` 汇总两个子报告及其 SHA-256。
未指定 case ID，执行完整矩阵：

```sh
uv run --project scripts --locked python -m vcore_scripts.protocol_fingerprint target/interop/runs/<fresh-run> --client-fingerprint <profile>
```

| 模板 / profile | 结果 | 秒 | 2026-09-25 UTC 起止 |
| --- | --- | --- | --- |
| Chrome133 / chrome | 57/57 PASS | 1971.231 | 13:46:49–14:19:40 |
| Chrome120 / chrome120 | 57/57 PASS | 1993.131 | 14:19:41–14:52:54 |
| Firefox120 / firefox | 57/57 PASS | 1967.160 | 14:52:54–15:25:41 |
| Safari16.0 / safari | 57/57 PASS | 1983.033 | 15:25:41–15:58:44 |

| 汇总报告 | SHA-256 |
| --- | --- |
| chrome | `f12b891c61a2415d9816a56a21b5f3ad3e70fc8f9a57ffcad8946dfca8428534` |
| chrome120 | `ef3b81039aa1974647a265367ab4564a210ed61ce161848eb133c5af0eaa657b` |
| firefox | `778569735336148ac2592b11823a8b22aa284caf44c34c7b123d5efdc6ad613e` |
| safari | `833aa53a2c84931c1a9caf67e15a6515df9440dd8d5af082486881e979e4bc63` |

四轮均使用官方 latest 入口取得同一实际对端身份；Caddy 依获准流程用官方 xcaddy 构建，
其余为官方预编译包。服务端、原站、观察端及对照入口全部在独占 Apple Container
host-only 网络，MTU 1500。各报告保存镜像 digest、流量断言、退出和清理记录。

| 对端 | 实际版本（Linux arm64） | 二进制 SHA-256 |
| --- | --- | --- |
| Mihomo | v1.19.31 / Go1.26.8 | `1b315bc038d05f84ee86d232f3c3d2b020b5044e9b971bb8fe215b6e6a2148f3` |
| V2Ray | 5.53.0 / Go1.26.1 | `2dac4128ef8edb0cf64d56dfead709684664d499a1081c4fc10af5ca79c78e60` |
| Xray | 26.3.27 / Go1.26.1 | `c2d20a7045250497083afea0d79db0672f6c89a25aaaf37c92de034d6b764b04` |
| Caddy | v2.11.4 / xcaddy v0.4.7 | `6f15e6d5fff9764c803fca1315e5b50bb05eb60e250809572950842098dbe150` |

## 受验来源与收尾锁文件

完整容器矩阵及首次最终结构报告的代码树为
`9a8016693d3d2ae2b70180424bff46171655040960b1e8bfe18c46bdb283dd6e`，
lockfile 为 `7f30266603963a3e4c65dc5d4be9e2ce439be5aeea4779e693e5f64bed27b482`。
测试期间没有修改输入。

最后审查发现更新 fork 时重新解析了五条 Windows 传递依赖边，将原有 windows-sys
0.61.2 非必要地选为 0.52.0/0.60.2。恢复父提交的五条选择后，Cargo.lock 相对父提交
仅剩 boring 三 crate 的 revision 更新。修正仅涉及上游 `cfg(windows)` 依赖，
七个 Apple/Android 目标的全部 feature、normal/build/dev 依赖树修正前后逐字节一致，
命令与边界见[构建记录](CF5-builds.md#收尾锁文件校正)。不重写既有报告或产物身份。

最终代码树：`43c0fff1fffb1002bde82875a234ff7d9f6189c2a9c1f21835d18108fef7a097`；
最终 lockfile：`45cc8ac15f7c15c68ce336cac77cc7da7f7d0ccdccfea5e00647b1b0b69874b1`。
此锁文件下重新执行 fmt、全目标 Clippy、全目标 `--no-run`、27 项安全、75 项配置、
24 配置下载腿隔离、6 项 feature-foundations、150 项脚本、Ruff、C header 和 TLS 审计，
全部通过；168 + 24 项纯内存结构/恢复检查也重新通过。

## 清单时限修订

原 CF5 单模板 900 秒未计入扩展后的 46 + 11 项、四组 20 轮静默检查及容器准备。
单模板整套预算修订为 3600 秒并记录实际起止时间；单项 240/150 秒、业务字节断言、
生命周期轮数和 5 秒静默期均不变。首轮超过旧预算，不记为旧时限门禁 PASS。

完整容器矩阵同一输入上的独立结构报告 SHA-256：
`95f43065463b34b56f7136dad727dd3a63d5f9976bcf6b9792f81609db4617dd`；
定向 H3 网关报告 SHA-256：
`7965098cd50e0ac2e231afb6dc082d65f392efe324ff4230994a974067614582`。

收尾锁文件上的 `selected-cf5-wire-lock-final-20260925/shape-results.json` SHA-256：
`d31a3004160b1ca56509e1ecb16a48fc43d5e135c13a9dd154fe0745ae5b27ed`。

# Shadowsocks 2022 出站

`outbound-shadowsocks` feature 使用原样官方 `shadowsocks-rust` 协议库，仅开放下列三种算法；配置纳入修订版 14。字段与示例见 [config.yaml](config.yaml)。本机协议与适配器验收见 [acceptance.md](acceptance.md)，不等同于完整组合或目标设备发布验收。

## 配置与密钥

`type: ss` 接受公共节点字段 `name`、`server`、`port`、`udp`、`dialer-proxy`，及必填 `cipher`、`password`。`udp` 默认 false；上游可引用具体节点或静态 select 组。

| cipher | 解码后密钥长度 | password |
| --- | --- | --- |
| `2022-blake3-aes-128-gcm` | 16 字节 | Base64 PSK 或 `iPSK1:…:iPSKn:uPSK` |
| `2022-blake3-aes-256-gcm` | 32 字节 | Base64 PSK 或 `iPSK1:…:iPSKn:uPSK` |
| `2022-blake3-chacha20-poly1305` | 32 字节 | 单一 Base64 PSK |

算法名称精确匹配。标准 Base64 可带或不带末尾 padding；空段、非法编码与密钥长度错误在配置验证时失败。AES 身份链保持声明顺序，末段是用户密钥；不 trim 凭据，不在错误或 Debug 中展示密钥。

## I/O 与关联状态

- 官方库仅包装 VCore 已有 TCP 流，UDP codec 使用单包有界交接；不调用官方库的物理 socket 创建接口。物理首跳继续经过共享 dialer、预解析端点、Android protect 和 Windows 绑定。
- TCP 按 16 KiB 部分写入交付 codec，确保首次目标头与负载落在协议帧上限内；读取或关闭写端先于首次写入时调用官方空首写，允许服务器先发或在客户端半关闭后响应。空首写遇到 Pending 时继续完成同一次握手，再关闭底层写端；已有负载首写不重复目标头。错误只保留错误种类与固定消息。
- UDP 在可取消发送前预留 packet ID，真实底层发送结束才报告成功；Pending 不触发重复编码，无后台发送队列。接收只交付完整数据报，并检查来源、认证、响应 payload 上限和关联 ID。
- 每个 UDP transport 保留随机 client session ID、递增 packet ID，以及最多两个 server session 的 8,128 包滑动重放窗口。旧 server session 最近一分钟仍有有效包时不替换；packet ID 即将溢出时重新生成 client session ID 并清空旧接收窗口。
- TUN 与 SOCKS5 的响应预算分别传入封装层，外层 wire 上限为 65,507 字节；超限不截断交付。关闭清空窗口并关闭底层 transport，不新增协议后台任务。
- 上游组选择使用同一次建链快照；DIRECT 使用已准备的代理服务器地址，代理上游保留逻辑服务器地址，不重新执行业务路由。

## 依赖与日志边界

官方 Git revision 固定为 `ab388c7466d21f979430e33cc9ef10e22fb05955`，关闭默认 features，仅启用 `aead-cipher-2022`；registry `shadowsocks-crypto` 为 `0.8.0`。没有协议源码补丁或研究目录 path 依赖。

仅允许 `shadowsocks → shadowsocks-crypto → aws-lc-rs → aws-lc-sys` 链使用 AWS-LC，来源、features 与反向依赖边由 `check tls-dependencies` 校验。TLS / REALITY 保持既有 rustls + ring；额外 AWS-LC 消费者、FIPS 和 2022-extra features 被拒绝。

官方库的 `log` 调用可能包含密钥或流量。启用 SS feature 时，通过 `log/max_level_off` 和 `release_max_level_off` 编译关闭该 facade 的全部日志；Cargo feature 合并意味着这也关闭同一依赖图中其他 `log` 调用，并非仅按 SS target 过滤。VCore 自身使用的 `tracing` 不受影响。上游 Debug 类型不通过公开适配器暴露。

UDP 重放窗口代码派生自官方项目中的 MIT 实现；来源、版权及完整许可文本见 [源码文件头](../src/outbound/shadowsocks/packet_window.rs)。发布时仍须审计目标平台的实际链接依赖图。

## 已知限制与验收边界

1. **上游 padding 风险未修补。** 锁定官方源码在空 TCP 首写、空 UDP payload 等路径扩展 padding 长度但没有显式初始化字节，存在把残留缓冲内容传给可解密对端的风险。原样复用并不等于该风险已修复；普通 echo 测试不能代替安全结论。
2. SS 2022 首次固定头不足单次读取长度时，官方库按协议的探测防护要求拒绝；不改为无限等待或 `read_exact`。
3. 当前 mihomo 服务端只暴露单 PSK。AES EIH 数据面通过独立测试中继逐层校验并剥离 1 / 2 层身份头，再把未解密的业务流量交给 mihomo；TCP/UDP 和错误身份拒绝均已执行。这不是 mihomo 原生 EIH 服务端支持，也不证明任意服务商的身份链部署。
4. 三算法活动 TCP/UDP Stop、绑定失败回滚、独立测速返回后的 socket 回收已在 macOS 验证。全协议组合压力与目标设备仍有独立门槛，见 [验收矩阵](acceptance.md)。

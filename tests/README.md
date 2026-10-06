# 测试入口

本仓库保留生产核心的配置、内存 IO、安全和生命周期回归，直接以定向 Rust 测试
执行。[VCore scripts](../scripts/README.md) 只编译核心与平台产物。协议互通、对端
下载、容器消费者以及内存/吞吐压力由独立的 [container-benchmark](https://github.com/OneXray/container-benchmark)
维护，通过显式 VCore checkout 指定被测核心；编译不依赖 benchmark 的安装或路径。

| 层次 | 保留内容 | 入口 |
| --- | --- | --- |
| 核心回归 | 严格配置、协议/TLS 内存 IO、局部上限、取消、FFI 边界和确定性回归 | 定向 cargo test |
| 编译 | 精简 feature、生产 feature、平台架构与全目标编译 | VCore scripts build |
| 编译工具回归 | 平台构建、产物身份与构建参数回归 | scripts/tests |
| 协议互通 | 官方 listener、生产 ABI 消费者、TCP/UDP 内容与代理路径 | 独立 container-benchmark interop |
| 性能评估 | Linux 原生 TUN、完整 CN 分流、吞吐/CPU/RSS/UDP 丢包/DNS | 独立 container-benchmark compare |
| 内存压力 | 显式规模 GeoData、加载与实际流量下的进程峰值 | 独立 container-benchmark stress |

在独立 benchmark 工程中执行，`PATH` 为显式 VCore checkout：

```sh
container-benchmark interop --source vcore=PATH
container-benchmark stress --source vcore=PATH --geodata-records 1280000
```

`interop --list` 可不提供 source，只列出测试，不运行互通。

所有服务端遵守[隔离规则](../docs/testing-isolation.md)。定向核心回归只运行不启服务的
内存用例；全目标测试编译使用 `--no-run`，ignored 不算通过。物理设备和正式安装
不由本地测试或 Linux 内存压力推导。

## 必要回归与独立输入

- h2_stream_regression：完整 END_STREAM 后 RST 不丢响应，未完成响应仍报错。
- stream_foundations 与 sing-mux：延迟响应遵守原建链期限；确认建立后允许继续读取。
- stream_shutdown：gRPC/legacy H2/池化 gRPC 和 XHTTP H1/H2 先送完再关闭；
  Stop 可取消待写，XHTTP 关闭有一秒上限。
- xhttp_h3_shutdown：纯内存 QUIC 背压下上传完成屏障、延迟握手、一秒关闭上限和 Stop。
  测试对端取消并 join 后台任务，不把 QUIC 关闭保留期当作客户端关闭期限。
- shadowsocks_backpressure：三算法 Pending 重试长度、读先于写时 codec 刷新，
  以及官方服务端对空首包零 padding 的确定性拒绝。不修改官方库。
- hysteria2_packet_ids：完成后重用 16 位分片 ID，不误丢后续业务包。
- shadowtls_config/stream：严格 v3、原生签名/Finished、残留 cover、背压/flush、
  读取取消和关闭期限；不能由内存回归推导真实官方对端互通。
- uot_config、shadowsocks_uot 与共享 outbound::uot：仅 v2、首包/读取门控、
  三算法 u16 边界、收发预算、受控 DNS、取消和 Stop。codec 上限不代表对端容量。
- security_capabilities：公开配置经真实 SecurityClient 在主/下载腿产生实际混合 share。
- tuic_config/tuic_memory 与 outbound::tuic：严格 v5、TLS exporter、无 ACK、
  双 UDP wire、分片/重组、关联 ID 退役、窗口/credit、Heartbeat 和 Stop。
- httpupgrade_config/httpupgrade_memory：普通/fast-open、ED、严格 101、部分写、
  首包恰好一次及原期限；已建连接不受建链期限限制。
- GeoData：iOS/tvOS 所选原始 GeoIP CIDR + GeoSite Domain 共用 1,280,000 条总保留
  额度的包含边界和超限截断，GeoIP 优先、余量用于 GeoSite，GeoIP 自身超限也保持总数。
  其他平台超旧数量/内存/文件额度的完整加载、整数溢出、缺失/损坏和原子快照。
  业务规则和 DNS policy 共用大小写归一后的唯一分类集合；重复引用不重复计分类，
  重复 CIDR 以及 Domain/Full/Plain（Substr）/Regex 都计数，未引用分类不计数。
  归一 code 排序与分类内原始记录前缀决定保留内容，预算耗尽的所选分类仍 available；
  超限不作为失败，合法更新可发布截断快照，两类资产共享总额度。截掉记录只检查外层
  wire/length，不解码/压缩 CIDR、校验内部 value/Regex 或编译；保留前缀仍严格校验。
  GeoIP 首次不可用不消耗有效额度；资产更新重分配整体额度，GeoIP 增长可减少
  GeoSite 保留量，真正失败的重载/更新保留旧整体快照/资产。
  分类异序/大小写定位与重载保持独立；TUN UDP 五元组独立固定 action，提示/GeoData
  更新只影响新流并释放旧快照；认证 QUIC 连接标识变更、同标识重传、逐目标空闲回收
  与响应刷新保持独立。域名 DNS 答案和非 TUN 路径继续更新，已有组 transport 不迁移。
  真实 fd-TUN 分流与进程峰值由独立 benchmark 压测；2026-10-06 的 1,280,000 条总
  GeoData 在 2 Gbps / 60 秒 / 1,000 QPS DNS 下 Linux RSS 为 42,557,440 bytes，
  仍有 UDP 丢包和 DNS 超时。输入、边界与指标见 benchmark README；旧 CN 121,009
  条观测和本轮特定分类结果都不能扩展为任意输入的内存保证。
  不把少量选路见证当作逐条规则语义证明，Linux RSS 不替代 Apple 真机 footprint。
- TUN UDP：reader 直接分流、慢关联隔离、TCP ingress Full 不阻塞 UDP/DNS；唯一 writer
  三通道公平/关闭/非法包隔离、平台接受前 DNS permit 生命周期、取消及关联/DNS 任务
  同步回收。纯 codec 的 MTU/族边界、TCP-only 与通用 endpoint 回归在 netstack 内。
- TUN 批次：首包等待后仅收已就绪包、最多 8 包、独立包边界、IPv6 策略及逐包流量、
  非法包邻居保留、EOF/取消前缀与不重放；Windows 队列/唤醒纯内存回归不替代设备验证。
  netstack 入站维护按有界批次摊薄，TCP 仍逐包 ingress；同目标端口 SYN 的流绑定、
  相邻 ICMP、输出满时未消费后缀及取消/关闭保持独立回归。
- 独立 ClientHello golden、Encryption 密码向量与 limits 输入保留，
  不能用待测实现生成期望或以声明清单替代行为。

历史宿主 listener fixture 只编译；实际网络互通只在独立 benchmark 的隔离容器中执行。
容器和实验生成文件在每轮结束后清理，仅保存脱敏文字结论。版本、源码/锁文件 hash、
命令、实测数据及清理结果必须写明；文字结论不能抵扣未经执行的设备或发布门禁。

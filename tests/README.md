# 测试入口

本仓库保留生产核心的配置、内存 IO、安全、生命周期和平台构建回归，
命令见 [scripts](../scripts/README.md)。容器编排、外部消费者、对端下载及内存/吞吐实验
由独立的 container-benchmark 工程执行，通过 `--vcore` 指定被测 checkout。
VCore 的日常检查和 CI 不依赖 benchmark 的路径或安装状态。

| 层次 | 保留内容 | 入口 |
| --- | --- | --- |
| 日常 | 严格配置、feature、协议/TLS 内存 IO、局部上限、取消、FFI 边界和确定性回归 | check core --profile debug/release |
| 构建 | 精简 feature、生产 feature、全目标编译 | check core --profile features |
| 工具 | 平台构建、产物身份、TLS 来源和有界子进程回收 | scripts/tests |
| 平台产物 | Apple/Android/Windows 架构、最低版本、hash 和原生 ABI | build --delivery 与 platform-artifacts/platform-abi |
| 外部网络与内存 | 容器协议互通、Linux 真实 TUN、完整 CN 分流、PID RSS 峰值、吞吐和长测 | 独立 container-benchmark |

所有服务端遵守[隔离规则](../docs/testing-isolation.md)。默认检查仅执行纯内存白名单，
全目标只编译 `--no-run`；ignored 不算通过。物理设备和正式安装不由本地测试推导。

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
  读取取消和关闭期限；真实官方对端由外部 benchmark 验证。
- uot_config、shadowsocks_uot 与共享 outbound::uot：仅 v2、首包/读取门控、
  三算法 u16 边界、收发预算、受控 DNS、取消和 Stop。codec 上限不代表对端容量。
- security_capabilities：公开配置经真实 SecurityClient 在主/下载腿产生实际混合 share。
- tuic_config/tuic_memory 与 outbound::tuic：严格 v5、TLS exporter、无 ACK、
  双 UDP wire、分片/重组、关联 ID 退役、窗口/credit、Heartbeat 和 Stop。
- httpupgrade_config/httpupgrade_memory：普通/fast-open、ED、严格 101、部分写、
  首包恰好一次及原期限；已建连接不受建链期限限制。
- GeoData：超旧数量/内存/文件额度的完整加载、整数溢出、缺失/损坏和原子快照。
  分类异序/大小写定位与重载保持独立；TUN UDP 五元组独立固定 action，提示/GeoData
  更新只影响新流并释放旧快照；认证 QUIC 连接标识变更、同标识重传、逐目标空闲回收
  与响应刷新保持独立。域名 DNS 答案和非 TUN 路径继续更新，已有组 transport 不迁移。
  完整官方 CN 的真实 fd-TUN 分流负载及生产宿主峰值由独立 benchmark 压测；
  不把少量选路见证当作逐条规则语义证明。
- TUN UDP：reader 直接分流、慢关联隔离、TCP ingress Full 不阻塞 UDP/DNS；唯一 writer
  三通道公平/关闭/非法包隔离、平台接受前 DNS permit 生命周期、取消及关联/DNS 任务
  同步回收。纯 codec 的 MTU/族边界、TCP-only 与通用 endpoint 回归在 netstack 内。
- TUN 批次：首包等待后仅收已就绪包、最多 8 包、独立包边界、IPv6 策略及逐包流量、
  非法包邻居保留、EOF/取消前缀与不重放；Windows 队列/唤醒纯内存回归不替代设备验证。
  netstack 入站维护按有界批次摊薄，TCP 仍逐包 ingress；同目标端口 SYN 的流绑定、
  相邻 ICMP、输出满时未消费后缀及取消/关闭保持独立回归。
- 独立 ClientHello golden、Encryption 密码向量与 limits 输入保留，
  不能用待测实现生成期望或以声明清单替代行为。

尚未迁移的历史宿主 listener fixture 只编译，不在 core 白名单，也不作为新的容器验收。
容器和实验生成文件在每轮结束后清理，仅保存脱敏文字结论。版本、源码/锁文件 hash、
命令、实测数据及清理结果必须写明；文字结论不能抵扣未经执行的设备或发布门禁。

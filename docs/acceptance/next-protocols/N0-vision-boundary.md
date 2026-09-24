# N0-C：Vision 公开 TLS 边界与原生互通

2026-09-24：N4 公开 `flow` 前的独立前置验证通过；不等于整个 N4 或完整 VLESS 已完成。历史 [N0 安全预验证](N0-security.md) 的失败与 NOT RUN 保留。

`target/interop/runs/n4-vision-boundary-20260924-v1` 的 6/6 容器用例 PASS，输入源树 `cf89187a5fe1b73368b0b3886461086d48dc2c8b86906417d6d7cf7d220565c3`，父提交 `403e5432faa56126d9722e6a25e88befa536d569`，Cargo.lock `8922605fc634d4709825730e9e7c27ad7279edc971db6e92374cb588f3b839f2`。源输入未变，四个所属容器均完成退出和清理。

- 官方 latest Mihomo v1.19.31，Linux arm64 / Go 1.26.8；下载压缩包 SHA-256 `9e0f11afbf38426b8bd88fdc594678f8161c57eccb4e1b77acb12b493904f1d4`，二进制 `1b315bc038d05f84ee86d232f3c3d2b020b5044e9b971bb8fe215b6e6a2148f3`。
- 外层标准 TLS / 经典 REALITY 分别验证内层非 TLS、TLS 1.2、TLS 1.3，以及 Vision XUDP。IPv4、IPv6、域名目标均执行；每条 TCP 数据路径双向 10 MiB，先读服务端首包，正常尾包在关闭前读完。
- 内层 TLS 1.3 的实际底层裸流读、写计数各大于 9 MiB；TLS 1.2 两者均为零，不以配置值或握手成功冒充 direct-mode。
- 该前置夹具在严格 YAML 解析后仅通过测试内 typed config 设置 Vision；公开 flow 当时仍拒绝。N4 后续测试必须使用公开配置重新执行，不能仅继承此结果。
- 公开 rustls reader + tokio-rustls AsyncBufRead 与自有单记录边界适配器解决预读；不使用私有缓冲、不改第三方。内存 TLS 对端按 1 / 3 / 65536 字节分片验证已解密明文排空、加密标记紧随裸流、发送前 flush，全部通过。

全部原站、TLS 目标及官方服务端位于隔离 hostOnly 容器；宿主只运行 VCore 消费者及观察驱动，没有启动测试原站。后续 N4 增补的 padding 分片/取消、非法帧、公开生命周期与关闭对照以最终 N4 证据为准。

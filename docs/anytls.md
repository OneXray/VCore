# AnyTLS 出站

本文描述当前 AnyTLS 客户端出站契约。VCore 支持 AnyTLS v2、兼容 v1 的会话、内置填充和 UoT v2。

## 配置

```yaml
proxies:
  - name: anytls-edge
    type: anytls
    server: anytls.example.com
    port: 443
    password: "private-password"
    sni: origin.example.com
    udp: true
    # dialer-proxy: socks-hop
rules:
  - MATCH,anytls-edge
```

- `name`、`type`、`server`、`port` 和 `password` 必填，`type` 固定为 `anytls`。
- `password` 长度为 1–1024 个 UTF-8 字节，不得出现在调试输出、日志或错误正文中。
- `sni` 可省略，默认使用 `server`；两者都必须是合法 IP 字面量或域名。
- `udp` 默认为 `false`；设为 `true` 后启用 UoT v2。
- `dialer-proxy` 使用与其他出站相同的无环代理图。
- 未列出的字段一律拒绝。TLS、ALPN、指纹、证书跳过、ECH、mTLS、填充和会话参数不可配置。

## TLS 与认证

AnyTLS 使用 VCore 的标准 TLS 客户端：

- 支持 TLS 1.3 和 TLS 1.2；
- 使用 WebPKI 根证书、规范化 SNI 和完整证书校验；
- 不发送 ALPN；
- 不支持 REALITY、伪造指纹、证书跳过、ECH 或客户端证书。

连接建立后，客户端依次写入 SHA-256 password hash、认证填充和首个会话批次。认证材料不得进入日志或错误信息。

## 版本协商

客户端首个 `Settings` 固定声明 `v=2`，并携带客户端版本和当前填充方案的 MD5。服务端返回合法的 `ServerSettings v>=2` 时按 v2 工作；未返回时按兼容 v1 的方式继续。

首个流与认证批次一同发送。复用空闲会话时：

- v2 会话写出 `SYN` 和目标后立即返回可用流，并启动最长 3 秒的 `SYNACK` 监视任务；
- 兼容 v1 的会话不等待 `SYNACK`；
- 非空 `SYNACK` 负载表示拒绝，整个物理会话随即失败；已经返回的流通过后续 I/O 暴露错误；
- `SYNACK` 超时、读写器关闭或协议错误都会销毁物理会话；
- 只有在 `open` 返回前发现空闲会话已经失效时，当前请求才允许新建一次物理连接。返回后的失败不会静默重拨。

未知流、错误控制流 ID、方向错误的帧、越界负载和非法 `ServerSettings` 都是会话级错误。远端诊断最多保留 256 字节。

## TCP 会话复用

- 一个物理会话同时只承载一个活动流。
- 流完整结束后，物理会话才进入空闲列表。
- 新请求优先复用序号最大的空闲会话。
- 空闲检查周期和超时均为 30 秒，不预热连接。
- 活动物理会话不设固定业务数量上限。
- 流 ID、会话序号耗尽或状态不一致时立即关闭对应会话。

写命令通道容量为 2。每个流的接收通道由运行时缓冲区容量推导且至少为 1。帧、填充、队列和诊断字符串都受固定上限约束，这些上限不开放为 YAML 参数。

## UDP over TCP

`udp: true` 时使用 UoT v2 目标：

```text
sp.v2.udp-over-tcp.arpa:0
```

UoT 固定采用数据报模式。首包携带 UoT 请求和第一份数据报，后续数据报各自编码 IPv4、IPv6 或域名目标，因此同一关联可以访问不同目标。协议帧负载最多 65,535 字节，同时继续受调用方给出的最终响应负载上限约束。

响应通道容量为 1。关闭、取消或丢弃 UoT 传输时，读取任务和底层流必须一起结束。

## 填充

客户端内置固定填充方案，不提供 YAML 配置。每个新物理会话取得一份不可变快照；服务端的合法 `UpdatePaddingScheme` 只影响之后创建的会话，不改变当前帧边界。非法更新只产生有界警告。

填充文本、每包条目数、停止值、逻辑填充量和帧负载均有固定上限。认证填充和后续数据填充使用同一份会话快照。

## 生命周期

每个运行时代理图为 AnyTLS 节点创建一个共享客户端和显式生命周期句柄：

```text
准备代理图
  -> 启动
  -> 按需打开 TCP/UoT 流
  -> begin_shutdown
  -> shutdown().await
  -> 释放代理图
```

`begin_shutdown` 是同步第一阶段屏障：禁止新流、清空空闲列表、取消客户端令牌并通知所有会话关闭。`shutdown` 随后等待空闲清理、会话读写器和 UoT 任务全部结束。运行时停止、准备回滚、测速工作器释放和失败清理必须使用同一路径。

AnyTLS 状态只属于创建它的运行时或测速工作器，不跨运行时共享。`measureDelay` 返回前必须完成私有代理图的关闭。

自动化和外部互操作的实际覆盖范围见 [验收矩阵](acceptance.md)。

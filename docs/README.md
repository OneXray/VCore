# VCore 文档

本文档集描述当前实现，不保存已退役 API、历史配置结构或第三方实现对比。源代码、测试和下列公共契约不一致时视为缺陷。

## 公共契约

1. [配置协议](config.yaml)：revision 11 的完整 YAML 示例与严格字段边界。
2. [Invoke API](invoke-api.md)：API v5 envelope、生命周期、所有权和平台 callback。
3. [AnyTLS outbound](anytls.md)：TLS、session、padding、TCP/UoT 和清理语义。
4. [REALITY V1 wire](reality-wire-protocol.md)：握手、认证、连接状态和失败边界。
5. [TUN 流量 Controller](controller-api.md)：Bearer 鉴权和四字段 snapshot。
6. [DNS 与 ICMP](tun-icmp-dns.md)：TUN DNS、cache、failover 和本地 Echo reply。
7. [GeoData](geodata.md)：规则、资产、更新、matcher 与资源上限。
8. [TUN 平台层](tun-platform.md)：fd、raw packet 和平台所有权。

## 平台与运行架构

1. [Windows VPN 平台边界](windows-vpn.md)：官方 VPN API、packet buffer、routes、物理绑定和 package 约束。
2. [Windows Session Runtime](windows-session-runtime.md)：Provider、Session Host、packet channel、lifecycle 和发布门禁。
3. [Runtime 资源策略](runtime-resource-policy.md)：跨平台局部边界、iOS telemetry 和真机验收。
4. [rustls REALITY 发布计划](rustls-reality-release.md)：自有 fork 的固定 revision、安全审查和发布步骤。

## 证据与维护

- [验收](acceptance.md)：当前自动化、实机证据和延期项目。
- [ADR](adr/)：已接受的架构决策。
- [开发上下文](../CONTEXT.md)：领域词汇与模块边界。
- [许可证与第三方声明](../THIRD_PARTY_NOTICES.md)：实际依赖、派生源码和许可证义务。

## 文档规则

- `config.yaml`、`invoke-api.md` 和各协议文档只描述当前版本。
- 历史结果不作为当前 PASS；验收必须记录环境、命令、结果和未执行项。
- Host tests、cross-build、模拟器和虚拟网络不能替代对应物理平台证据。
- 公共行为先更新契约和测试，再修改实现；未知字段和旧结构继续 fail closed。

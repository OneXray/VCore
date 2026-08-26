# VCore 文档

本目录只描述当前实现和仍然有效的开发约束。历史方案、阶段计划、一次性实验记录、旧包哈希和第三方实现对比不属于公共文档；源代码、测试与本文档不一致时视为缺陷。

## 公共契约

1. [配置协议](config.yaml)：配置修订版 11 的完整 YAML 示例和严格字段边界。
2. [Invoke API](invoke-api.md)：API v5 的请求格式、生命周期和平台回调。
3. [AnyTLS 出站](anytls.md)：TLS、会话复用、填充、TCP/UoT 和清理语义。
4. [REALITY V1 协议](reality-wire-protocol.md)：握手、认证、连接状态和失败边界。
5. [TUN 流量 Controller](controller-api.md)：Bearer 鉴权和四字段流量快照。
6. [DNS 与 ICMP](tun-icmp-dns.md)：TUN DNS、缓存、故障转移和本地 Echo Reply。
7. [GeoData](geodata.md)：规则、资产更新、匹配器和资源上限。
8. [TUN 平台层](tun-platform.md)：文件描述符、原始 IP 包和平台所有权。

## 平台与运行架构

1. [Windows VPN 平台边界](windows-vpn.md)：官方 VPN API、包缓冲区、路由、物理网络绑定和安装包约束。
2. [Windows 会话运行时](windows-session-runtime.md)：Provider、Session Host、包通道和生命周期。
3. [运行时资源策略](runtime-resource-policy.md)：局部容量、取消、回收和遥测原则。
4. [rustls REALITY 依赖](rustls-reality-release.md)：自有 fork 的边界和发布要求。

## 证据与维护

- [验收矩阵](acceptance.md)：自动化覆盖、实机覆盖和未完成的发布门禁。
- [架构决策](adr/)：仍然有效的系统级决策。
- [开发上下文](../CONTEXT.md)：领域词汇和模块边界。

## 文档规则

- 协议文档只描述当前版本；被删除的字段和历史兼容结构不重复收录。
- 技术标识符、配置键、API 名称和线上协议值保留原文，其余说明使用中文。
- 验收文档保留可复现矩阵，不累积候选包版本、临时进程号或一次性性能结果。
- 主机测试、交叉编译、模拟器和虚拟网络不能替代对应物理平台证据。
- 公共行为变化必须同时更新实现、测试和相关契约。

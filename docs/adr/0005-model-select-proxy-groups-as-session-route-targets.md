---
status: accepted
---

# ADR 0005：将 select 代理组建模为会话路由目标

VCore 把首版 `select` 代理组建模为位于不可变代理节点与 `dialer-proxy` 图之上的命名路由目标。组拥有一个有序、非空的直接成员列表，成员可以是代理节点、嵌套 `select` 组、`DIRECT` 或 `REJECT`；省略 `default-selected` 时选择第一项，显式值必须精确命中一个直接成员。普通规则、最终 `MATCH` 和 DNS 路由可以引用组，`dialer-proxy` 与 `measureDelay` 仍然只接受代理节点。

组选择只属于当前 VCore 运行会话，由调用方在下一次配置中重新提供。每次 `connect_tcp` 或 `open_datagram` 进入组时只读取一次选择；成功切换只影响提交后才进入组的新调用，不迁移已有 TCP、不替换已有 UDP transport，也不清理 DNS cache 或已有 DNS TCP connection。已经读取旧选择但仍在建链的调用继续使用旧成员；被选成员失败时原样返回错误，不在组内隐式 failover。

代理组位于 `Dispatcher` seam，具体协议节点及其 `dialer-proxy` graph 继续由 `OutboundConnector` 实现。这个边界避免让运行时选择渗入协议建链，并使“组不能作为 `dialer-proxy`”成为明确、可验证的约束。

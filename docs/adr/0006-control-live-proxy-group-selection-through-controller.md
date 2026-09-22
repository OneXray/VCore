---
status: accepted
---

# ADR 0006：只通过 Controller 控制代理组的实时选择

VCore 首版只通过 Controller 暴露代理组的实时选择，不新增 Invoke 方法，也不扩展 Windows 控制管道。Controller 采用 mihomo `select` 的核心调用形状：`GET /group`、`GET /group/{name}`、`GET /proxies/{name}` 和 `PUT /proxies/{name}`；PUT body 为 `{"name":"member"}`，成功返回空的 `204`。组状态只承诺 `name`、`type`、`all`、`now`，不宣称兼容完整 mihomo Dashboard API。

Windows 的实际运行时位于独立 Session Host，Apple 与 Android 的运行时位于 Invoke owner 背后；Controller 是现有平台中唯一能统一到达实际运行会话的 Adapter。组路由可以在无 TUN 的本地代理运行时中使用，`/traffic` 仍只在存在 TUN 统计时提供。

配置同时包含代理组和 Controller 时，必须为整个 Controller 配置 Bearer secret。请求使用精确名称和严格、有界的 JSON，任何失败都不得改变选择。没有 Controller 的代理组配置仍然有效，但本次会话中没有公开的实时切换入口；调用方在成功切换后自行持久化下一次启动所需的 `default-selected`，持久化失败不回滚已经成功的运行时选择。

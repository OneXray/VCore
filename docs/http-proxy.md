# HTTP 代理入站

HTTP 入站通过当前 Session 的 Dispatcher 使用规则、节点和静态 `select` 代理组。实现位于 `src/inbound/http/`；公共字段见[配置协议](config.yaml)。

## 监听与认证

- `port` 省略或为 0 时不启用，1–65535 时启用；整个配置须启用 HTTP、SOCKS5 或 TUN。
- `allow-lan` 默认为 false，绑定 `127.0.0.1`；开启时绑定 `0.0.0.0`。当全局 `ipv6: true` 时，同时绑定同端口的 `::1` 或 `::`，IPv6 socket 固定为 v6-only。
- 操作系统明确报告地址族 / 协议不支持时可省略 IPv6 socket；地址占用、权限和其他绑定错误使整个启动失败。`ipv6: false` 不创建 IPv6 listener。
- `authentication` 省略或为 `[]` 时，本机模式不要求认证；提供时必须恰好一项 `user:password`。按第一个冒号分隔，用户名与密码各为 1–255 UTF-8 字节，密码中的后续冒号保留，不 trim。显式 `null` 不是省略或空列表。
- `allow-lan: true` 强制要求有效凭据；配置共享或非空凭据时必须有启用的 HTTP 或 SOCKS5 入站，二者共用这一组凭据。HTTP 共享通过 Basic 认证，不提供链路加密，只适合可信网络。
- 配置了凭据就对每个请求独立认证，不继承同一连接前次请求的授权。缺失、错误、重复或格式不合法的 `Proxy-Authorization` 返回 `407` 并关闭连接，不建立上游。
- Controller 保留独立的回环地址、Bearer secret 和路由，不随共享开关开放。

配置片段（与节点、规则等共同使用）：

```yaml
port: 1080
allow-lan: false
ipv6: true
authentication:
  - "proxy-user:proxy-password"
```

## 普通转发

支持 HTTP/1.0 和 HTTP/1.1 的绝对形式 `http://host[:port]/path?query`。每个请求分别认证、确定目标、选路并建立上游；上游连接不跨请求复用。目标来自绝对 URI，转发成 origin-form 并重建 Host。

客户端连接可依次发送多个请求，也可顺序预发送。固定读取缓冲区保存下一请求的预读字节，正文严格按照当前消息边界消费。只有请求允许 Keep-Alive、上传完成、响应有明确边界时才继续下一请求；不会把旧目标连接用作下一请求的上游。

正文按流处理：

- `Content-Length` 精确转发对应字节数，未带正文长度的普通请求视为空正文。
- `Transfer-Encoding: chunked` 逐块解码边界并重编码，支持合法扩展语法和 trailer；扩展不向下一解析器透传，合法 trailer 保留。
- HEAD、1xx、204、304 按无正文处理；1xx / 204 携带正文定界字段时失败关闭，HEAD / 304 可保留描述所选表示的长度。
- 转发 HTTP/1.1 的 `100 Continue` 等临时响应。上传和读取响应并行，目标提前给出最终响应时终止上传、转发响应并关闭客户端连接，不把剩余正文作为新请求。
- 普通响应无长度字段时由上游 EOF 定界，响应结束后关闭客户端连接。向 HTTP/1.0 客户端交付分块响应时去块并以关闭连接定界。

歧义长度、重复 Content-Length、CL/TE 并存、非法分块、正文截断、非法控制字符和超限解析均失败关闭，不尝试恢复到下一请求。内部诊断字段、代理认证字段、Connection 指名字段及其他逐跳字段不会泄漏给目标；正文 trailer 不能携带认证、路由、消息定界或内部诊断字段。

消息定界与连接管理依据 [RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3)，逐跳字段依据 [RFC 9110 §7.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1)。VCore 对歧义输入采用严格拒绝策略。

## CONNECT 与 Upgrade

CONNECT 只在 Dispatcher 成功建立上游后返回 `200 Connection Established`。请求头后已经读到的数据保留，随后与新数据一起进入双向转发。建链失败返回对应错误，不提前确认隧道。

HTTP/1.1 Upgrade 只接受无正文的请求。收到合法 `101`、Connection / Upgrade 字段一致且目标选择的协议在请求列表中时，才进入双向隧道。双方预读字节及 TCP 半关闭保留；非 `101` 响应按普通 HTTP 消息处理，非法切换返回 `502`。

内部测速诊断只在**认证通过、监听地址为回环、客户端为回环、CONNECT 显式请求诊断**时返回。无认证的本机入口和共享入口均不返回内部错误详情，即使连接来自本机。

## 生命周期与局部资源边界

- 先取得 Controller 和全部业务地址族的监听 socket，再启动接收任务；任何一步失败释放已绑定 socket。业务连接按需创建，不设置全局连接数量准入上限。
- 单个请求 / 响应头最多 32 KiB、100 个字段，读头总期限 10 秒；出站连接期限 10 秒。
- 每个方向的预读 / 正文复制缓冲区为 8 KiB，正文长度不决定分配大小。chunk-size 行最多 1 KiB，trailer 合计最多 8 KiB / 100 个字段；每个最终响应前最多 16 个临时响应。
- 正文每次读取 / 写入的空闲期限为 30 秒。上传期间并行等候响应，响应开始后使用独立读头总期限；上传结束后等待响应也有 10 秒期限。
- Stop 覆盖读头、认证响应、建链、正文、CONNECT 和 Upgrade，取消后等待全部连接任务退出；端口在 Stop 返回后可重新绑定。

自动化与 mihomo 双向进程互通的入口见[验收矩阵](acceptance.md)与[脚本说明](../scripts/README.md)。回环双栈测试不等于真实局域网或物理 IPv6 验收。

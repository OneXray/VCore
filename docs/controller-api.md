# TUN 流量 Controller API

Controller 只提供当前 TUN 会话的单次 HTTP 流量快照，不提供持续推送、连接明细、配置修改或其他管理接口。

## 配置

```yaml
external-controller: 127.0.0.1:9090
secret: "vcore-runtime-secret"
```

- 省略 `external-controller` 表示不启动 Controller，此时不能单独配置 `secret`。
- `external-controller` 只接受回环地址，并且只能与 `tun.enable: true` 一起使用。
- `secret` 可省略；一旦出现就必须是非空 Bearer token。
- `measureDelay` 的节点配置不能包含这两个字段。
- `validateConfig` 只校验字段；`prepare` 不监听端口；`start` 绑定端口，绑定失败则启动失败。
- `stop` 和 `destroyInstance` 关闭监听器。

Controller 与 TUN 会话同生共灭。每次会话启动都会新建统计状态并把全部计数清零。宿主应为每次运行选择专用端口和随机密钥，密钥不得写入日志或错误正文。

## Bearer 鉴权

配置 `secret` 后，请求必须携带：

```http
Authorization: Bearer vcore-runtime-secret
```

要求：

- scheme 必须是 `Bearer`；
- token 必须与当前会话配置完全一致；
- 缺失、格式错误或不匹配都返回 `401 Unauthorized`；
- 比较过程不能通过日志、响应或明显的提前返回时序泄漏 token。

未配置 `secret` 时不要求 `Authorization`。Controller 不使用 HTTP Basic；顶层 `authentication` 只属于可选 HTTP 代理监听器。

## `GET /traffic`

授权请求立即返回一次 `application/json` 快照：

```json
{
  "up": 1024,
  "down": 4096,
  "upTotal": 65536,
  "downTotal": 262144
}
```

字段均为非负整数，单位为字节：

- `up`：最近一个完整的一秒窗口内，从宿主 TUN 进入 VCore 的原始 IP 包字节数；
- `down`：最近一个完整的一秒窗口内，由 VCore 写回宿主 TUN 的原始 IP 包字节数；
- `upTotal`：本次 TUN 会话的累计上行字节数；
- `downTotal`：本次 TUN 会话的累计下行字节数。

Apple utun 的四字节包信息头不计入统计。统计只覆盖跨过 TUN L3 边界的包，包括 TUN DNS 和 ICMP；不重复计算 TLS、XHTTP 或其他代理封装，也不包含 HTTP 代理入站、GeoData 下载、Controller 请求和 `measureDelay`。

请求不会等待下一次采样，不保持分块响应，不升级 WebSocket，也不为调用方保存“上次读取”状态。首个采样窗口完成前和空闲窗口内，`up`/`down` 为 0；累计值在同一会话内单调不减并采用饱和语义。

## 边界

Windows 的 TUN 运行时位于独立 Session Host 时，App 通过回环 HTTP 访问 Controller。流量查询不是 `VCoreInvoke` 方法，不携带 `instanceId`，也不占用 Invoke 命令锁。

当前协议只定义符合鉴权要求的 `GET /traffic`。其他路径和方法均不属于公共协议。

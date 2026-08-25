# TUN 流量 Controller API

状态：当前公共契约。Controller 只提供 TUN 流量的单次 HTTP snapshot；不实现持续响应、WebSocket、连接明细、配置修改或其他管理 endpoint。

## 1. 配置

TUN 运行配置可选写出顶层 Controller 地址，并可选配置 secret：

```yaml
external-controller: 127.0.0.1:9090
secret: "onevcore-runtime-secret"
```

- 省略 `external-controller` 表示不启动 Controller；此时不允许单独出现
  `secret`。
- `external-controller` 可以单独出现，此时不要求鉴权。
- `secret` 只允许在 `external-controller` 存在时出现；一旦出现就必须是合法的
  非空 bearer token。
- 这两个字段只属于启用了 `tun` 的运行配置。非 TUN 公共实例和
  `measureDelay` 的 node-only 配置都不能使用它们。
- `external-controller` 是 Controller 的 HTTP 监听地址。VCore 当前子集只接受
  loopback 地址。OneVCore App 固定使用本次运行专用端口，不把 Controller 暴露到
  LAN。
- OneVCore Simple Profile 启用 TUN 流量统计时，同时写入本次运行专用的随机
  `secret`。
  配置、日志和错误不得输出 token 原文。
- `validateConfig` 只校验字段；`prepare` 不监听端口。配置了 Controller 时，
  `start` 创建监听器，绑定失败则本次 TUN 启动失败；`stop` 或
  `destroyInstance` 关闭监听器。

Controller 与当前 TUN session 同生共灭，不是进程级常驻管理端口。每次 TUN
session 重新启动都创建新的统计状态并将全部计数清零。

## 2. Bearer 鉴权

配置了 `secret` 时，每个请求必须携带：

```http
Authorization: Bearer onevcore-runtime-secret
```

鉴权规则：

- scheme 必须是 `Bearer`；
- token 必须与当前配置的 `secret` 完全一致；
- 缺失、格式错误或 token 不匹配都返回 `401 Unauthorized`；
- token 比较不得通过日志、响应内容或明显的提前返回时序泄漏 secret。

`external-controller` 单独出现且没有 `secret` 时，Controller 不要求
`Authorization` header；请求即使携带 header 也不能把它解释成其他鉴权协议。

Controller 不使用 HTTP Basic authentication。顶层 `authentication` 只属于可选
HTTP proxy listener，与 Controller 的 `secret` 没有共享或回退关系。

## 3. `GET /traffic`

授权请求立即返回一个 `application/json` 单次 snapshot，然后结束 HTTP response：

```json
{
  "up": 1024,
  "down": 4096,
  "upTotal": 65536,
  "downTotal": 262144
}
```

四个字段都是非负整数，单位为 byte：

- `up`：最近一个已完成的一秒采样窗口内，从宿主 TUN 读入 VCore 的 raw-IP
  packet byte 数；它表示该窗口的上传速度。
- `down`：最近一个已完成的一秒采样窗口内，由 VCore 写回宿主 TUN 的 raw-IP
  packet byte 数；它表示该窗口的下载速度。
- `upTotal`：当前 TUN session 启动以来累计的上传 raw-IP byte 数。
- `downTotal`：当前 TUN session 启动以来累计的下载 raw-IP byte 数。

Apple utun 的四字节 packet-information header 不计入流量。统计只覆盖实际跨过
TUN packet I/O 边界的 L3 packet，因此包含经 TUN 进入的数据、DNS 和 ICMP，
但不重复计算 proxy transport/TLS/XHTTP framing，也不包含 HTTP proxy inbound、
GeoData 下载、Controller 自身请求或 `measureDelay`。

`GET /traffic` 只返回一次当前 snapshot：

- 不等待下一个 tick；
- 不保持 chunked stream；
- 不升级 WebSocket；
- 不按调用方维护“上一次查询”状态。

首个一秒窗口完成前 `up`/`down` 为 `0`。空闲窗口也返回 `0`；累计值保持不变。
计数在同一 TUN session 内单调不减并采用饱和语义，不能溢出后回绕。

## 4. API 边界

TUN 运行在独立进程时，App 通过 loopback HTTP 访问该进程内的 Controller。流量
查询不是 `VCoreInvoke` method，不携带 `instanceId`，不占用 Invoke command
admission，也不允许 App 进程尝试查询另一份 VCore runtime 的实例表。

当前 Controller 只接受符合当前 secret 策略的 `GET /traffic`。其他 path 不属于
协议；对 `/traffic` 使用其他 HTTP method 也不属于协议。后续若增加 endpoint、
持续订阅或非 TUN 统计，必须先更新配置协议、本文和验收矩阵。

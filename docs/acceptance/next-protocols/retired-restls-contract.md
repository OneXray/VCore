# Restls

> 历史契约：2026-09-26 按用户决定撤回。schema26 已删除此功能及配置入口；
> 下文仅保留旧实现的语义与证据，不是当前可用能力。

schema25 / Invoke v5。VLESS 主腿和 XHTTP H1/H2 独立下载腿可通过 `restls-opts`
选择 Restls。**N7.4 子包验收正在进行，生产接线不代表完整 N7 签收。**

```yaml
tls: true
servername: cover.example
restls-opts:
  password: example-password
  version-hint: tls13
  restls-script: "250?100<1,350~100<1,600~100,300~200,300~100"
```

## 配置与身份

- 密码必填，1–65535 UTF-8 字节，不裁剪空格；日志、Debug 和错误不回显。
- hint 必填，精确值 `tls12` / `tls13`，选择认证格式，不强制协商版本；原生范围
  为 TLS1.2–1.3。cover 应与格式相符。
- 脚本缺省或空串使用上方协议默认。仅含 ASCII 空格/逗号表示空脚本，不等同缺省。
  未知字段、null、错型在 IO 前拒绝。
- 要求 `tls: true`，同腿与 REALITY/JLS 互斥；不支持 Vision、H3、客户端证书身份。
  cover 仍通过共享证书验证：pin/name 优先于 `skip-cert-verify`。
- 两种 hint 均支持选定的 `client-fingerprint` 模板。无模板使用原生 boring hello，
  不称为 Mihomo 默认 Chrome 的逐字节仿真。

下载对象缺省继承整个主腿对象，存在时完整替换，须同时给密码和 hint。
`restls-opts: {}` 显式清除；主腿空对象拒绝。TLS 叶字段独立继承/覆盖，切换
模式必须清除旧身份与不兼容证书策略。清除后普通 XHTTP 恢复 TLS1.3 策略。

## 脚本与资源

逗号分隔的 `长度[?范围或~范围][<响应数]`，整数非负；`?` 在节点构建时采样一次，
`~` 每条记录采样，上界不包含，范围 0 不随机。`<N` 请求响应并等待下一条认证
记录，`<0` 也会等待；不是休眠计时器。忽略空段/ASCII 空格，其他空白与缺失数字拒绝。

脚本最多 4096 字节、64 条，响应数 0–254；最大可能目标长度 16364 字节，预留
12 字节认证头及 TLS1.2 GCM 的 8 字节 nonce。此边界拒绝 Go 解析器能接受、但
可能因过大 padding 触发写入 panic 的目标，不静默截断。空目标生成 19–118 字节
随机 padding，脚本结束后按数据分片，不循环脚本。

发送 body 上限 16384、读取密文上限 18432；发送缓存受共享 TLS buffer 预算约束，
最多 16384，接收完整记录只保留一条。等待时写入背压，不无限追加数据；响应数
有界，没有后台任务。既有取消/同步 Stop 保持不变，关闭 5 秒上限包括脚本等待与
flush；发送原生 close-notify 后不主动对底层 FIN，不等待对端 close-notify。
收到请求回复的记录时，先恢复被暂停的应用发送，再发送完整数量的脚本回复；
恢复发送不抵扣回复数量，与 Mihomo 的客户端调用顺序一致。

## 原生认证与依赖

使用已发布自有 boring revision `d8d6d92912a5e6bd1c43f4c8e1c78fd4a2d74544`
的 opt-in Restls hook。ECDHE、证书策略、ServerKeyExchange、CertificateVerify
和 Finished 留在原生 TLS；额外认证失败不返回普通 TLS 通道。不导出 TLS 私钥
或 traffic secret，不在外部改写 ClientHello，不恢复 rustls fork。

记录复用官方 Rust `blake3`，固定 UTF-8 context `restls-traffic-key` 无需
Encryption 的二进制 context C FFI；派生密钥零化。握手后保留原生 TLS，延迟
cover 记录必须通过原生认证，其明文不交给业务；不试探计数器直到 MAC 碰巧通过。

cover TLS 完成后，业务切换到 Restls 记录：BLAKE3 认证和长度字段掩码**不是业务
加密**，payload 不再由 cover TLS 的 AEAD 保护。需要业务保密性时须依赖内层协议
（例如 VLESS Encryption 或应用 TLS）；不能把 Restls 单独描述为加密隧道。

`tls12` hint 的缓存为节点独占，纳入运行时四票据总预算；`tls13` hint 关闭恢复
和 ticket 请求。独立下载腿拥有自己的身份、脚本采样和缓存。连接器只包装调用者
提供的 IO，不创建 socket/resolver。参见 [TLS 依赖](../../tls-dependencies.md)、
[VLESS](../../vless.md) 与 [隔离验证](../../testing-isolation.md)。

# VLESS JLS

配置修订版 24 为 VLESS 主连接和 XHTTP 独立下载连接增加 `jls-opts`。
JLS 提供独立的共享凭据身份认证，仍使用完整原生 TLS 1.3 数据通道；它不是
`skip-cert-verify`，也不是在普通 TLS 失败后切换到裸流。

```yaml
type: vless
tls: true
jls-opts:
  username: synthetic-user
  password: synthetic-password
# client-fingerprint: chrome
```

## 配置

- 对象出现即启用，两项必须都是非空字符串，各 1–65,535 个 UTF-8 字节，不 trim。
  主连接不接受空对象；未知字段、null、错型、缺项及超限在 IO 前拒绝。
- 必须 `tls: true`。同一腿不能混用 REALITY、标准证书策略或客户端证书；
  ECH、其他安全封装、Vision 和 HTTP/3 也不属于此组合。
- `servername`、有序 ALPN、传输必需 ALPN 与已支持的七值/四模板
  `client-fingerprint` 沿用共享配置，不增加全局默认或别名。
- `download-settings.jls-opts` 缺省继承整个身份；非空对象必须完整替换两项，
  `{}` 清除，不能按叶继承另一个身份的密码。其他下载字段独立覆盖。
- 切换下载安全模式须显式清除旧身份及冲突证书策略；设置新对象不会自动删除旧对象。
  两腿仍必须汇入同一个原生 XHTTP handler 的会话表。

## 认证与所有权

锁定的自有 boring JLS hook 认证实际 ClientHello/ServerHello，由原生 TLS
完成 transcript、CertificateVerify、Finished 和记录保护。共享凭据替代 WebPKI
身份，但不会跳过握手签名或 Finished。普通 TLS 证书、错误凭据、篡改握手、
TLS 1.2 和 HRR 都不能满足 JLS；失败不发伪装 HTTP 探测、不重发业务、不回退 DIRECT。
模板保留 TLS 1.2 的声明下限，实际成功协商始终必须 TLS 1.3。

每条腿的连接器身份不可变；不启用 TLS 恢复、PSK 或 early data。自有凭据副本
使用清零容器，原生临时材料按握手/失败清理；不宣称擦除所有配置 String 副本。
连接器只包装既有 Dialer/上游交付的受控 IO，不创建 resolver、socket、后台任务
或额外连接池。建链期限、取消、ALPN 检查和同步 Stop 继承现有运行时。

JLS 继续承载 TLS 记录，CloseWrite 沿用共享 TLS 有界关闭；XHTTP 保持整流关闭。
Encryption 位于外层传输内，身份彼此独立，不能由单层成功推断组合验收。

## 验证边界

互通优先官方 latest Mihomo `jls-config`，协议端、原站与对照入口全部容器化。
Mihomo v1.19.31 无指纹 gRPC 的 ALPN 状态读取存在已复现缺口：关闭语义使用
其 Chrome 指纹路径作显式标注的对照，VCore 待测节点仍保持无指纹，不冒称
完全同配置差分，也不更改第三方实现。
[JLS 验收记录](acceptance/next-protocols/N7-jls.md)区分独立 fork、VCore 公共消费者、
下载腿、共享回归与生产构建。JLS 子包不代表 ShadowTLS、ECH、N7.5 或
完整 N7 已签收，也不替代 Windows 原生、设备/TUN、远端 CI 与发布门禁。

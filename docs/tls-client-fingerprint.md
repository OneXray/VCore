# TLS 证书与客户端指纹

配置修订版 19 区分两个独立字段：

| 字段 | 含义 | 接受值 |
| --- | --- | --- |
| `fingerprint` | 服务端证书 DER 的 SHA-256 pin | 64 个十六进制字符，可带冒号 |
| `client-fingerprint` | 客户端 ClientHello 的命名模板 | `chrome120`；空串关闭 |

`client-fingerprint` 省略时关闭，大小写敏感；未知名称、`null`、错型全部拒绝。
不把 `chrome` 等未实现名称静默映射到另一模板。该字段是节点级选项，无全局默认。

## 适用范围

AnyTLS、Trojan、VMess + TLS、VLESS + TLS/经典 REALITY 使用同一共享连接器。
TCP、WS、gRPC、HTTP 首包伪装、legacy H2、Vision、XHTTP H1/H2 仍遵守各自的协议约束。
关闭 TLS 时不能携带该字段。SOCKS5、SS 2022 不接入 TLS 指纹。

XHTTP `download-settings.client-fingerprint` 缺省继承主腿，显式名称覆盖，空串清除。
下载腿即使与主腿使用同一服务器，也拥有独立的 TLS 策略、身份和缓存。
切换到明文或 H3 前必须显式清除继承的非空 profile；H3 不支持此模板，不回退 H2。

```yaml
type: vless
tls: true
client-fingerprint: chrome120
# fingerprint: <certificate SHA-256> # 与 ClientHello 模板独立
```

## 后端与认证

- 未启用指纹的标准 TLS 和 QUIC 使用 crates.io 官方 rustls + ring，不依赖 rustls fork。
- 命名指纹的标准 TLS，以及所有经典 REALITY，使用锁定提交的自有 boring fork。
- 普通 TLS 两条路径共用同一个 WebPKI 证书验证器和发布信任根；叶 pin、非叶信任锚、
  独立验证名、skip 优先级不变。TLS 握手签名仍由各自后端强制验证。
- VLESS mTLS 继续使用配对的内联 PEM，密钥匹配在使用 IO 前检查；profile 不修改身份。
- REALITY 仅允许自身临时证书认证，不能混用 pin/skip/mTLS 或降级到普通站点证书。
- 连接器只包装 Dialer/上游交付的 IO，不解析 DNS、不创建 socket、不绕过平台 protect。

## `chrome120` 边界

模板由 fork 固定密码套件、经典组、签名算法、GREASE、扩展排列、SCT/OCSP、
ECH GREASE、Brotli 证书解压以及在提供 `h2` 时的旧码点 ALPS。
TLS 版本范围、SNI、ALPN、证书策略、身份和恢复预算仍由节点及传输决定。
因此名称表示版本固定的 TLS 模板，不承诺完整浏览器行为或所有上下文的逐字节相同。

不模拟浏览器 HTTP/2 SETTINGS、QUIC 参数、实际 ECH 或混合后量子 REALITY。
当前 HTTP 驱动不导入 TLS ALPS 中的应用设置，因此**非空 ALPS 响应明确失败**；
未协商或协商空设置可用。Brotli 解压输出和原生证书消息上限均为 128 KiB。

## 所有权与关闭

节点的 SNI、ALPN、验证策略、mTLS 身份、版本范围、profile 和 SSL 上下文不可变。
每次独立构造建立独立缓存，clone 只共享同一节点。标准 TLS 的运行时票据总预算为 4；
TLS 1.3 票据只消费一次，TLS 1.2 会话也计入预算，过期票据清除，零预算关闭恢复。
握手及应用层 ALPN 策略通过前，暂存票据不会进入节点缓存。REALITY 始终不恢复。

CloseWrite 刷新 close_notify 最多 5 秒，保留底层连接和读方向；重复关闭幂等，
关闭后拒绝写入。Vision direct 切换保留同一 TLS 记录边界，先排空明文/刷新密文，
不向裸流插入外层 TLS alert。XHTTP 仍按其整条逻辑连接关闭契约工作。

## 验证与发布

验证使用真实公开配置、共享连接接口和独占容器内的原生协议对端；
编解码及纯内存 TLS 测试不启动宿主监听器。命令见 [构建与检查](../scripts/README.md)，
当次执行范围见 [验收矩阵](acceptance.md)。设备、性能、体积和发布许可证审查各自独立，
本地互通或交叉编译不替代这些门禁。

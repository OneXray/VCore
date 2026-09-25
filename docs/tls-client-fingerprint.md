# TLS 证书与客户端指纹

配置修订版 20 区分两个独立字段：

| 字段 | 含义 | 接受值 |
| --- | --- | --- |
| `fingerprint` | 服务端证书 DER 的 SHA-256 pin | 64 个十六进制字符，可带冒号 |
| `client-fingerprint` | 客户端 ClientHello 的命名模板 | 下列七值；空串也关闭 |

| 公开值 | 实际模板 |
| --- | --- |
| `none` | 关闭命名指纹，不关闭 TLS 或 REALITY 认证 |
| `chrome` | Chrome133 |
| `chrome120` | Chrome120（固定） |
| `firefox` / `firefox120` | Firefox120 |
| `safari` / `safari16` | Safari16.0 |

节点省略时关闭，显式启用推荐 `chrome`；这是节点级选项，无全局默认。
大小写敏感，未知名称、`null`、错型全部拒绝；不接受 `chrome133`、`safari16.0`、
移动端、随机或 PSK/PQ 专用名称。短名只随显式依赖升级和验收变更，不随 OS 自动选择。

## 适用范围

AnyTLS、Trojan、VMess + TLS、VLESS + TLS/经典 REALITY 使用同一共享连接器。
TCP、WS、gRPC、HTTP 首包伪装、legacy H2、Vision、XHTTP H1/H2 仍遵守各自的协议约束。
关闭 TLS 时不能携带该字段。SOCKS5、SS 2022 不接入 TLS 指纹。

XHTTP `download-settings.client-fingerprint` 缺省继承主腿，显式名称覆盖，`none` / 空串清除。
下载腿即使与主腿使用同一服务器，也拥有独立的 TLS 策略、身份和缓存。
切换到明文或 H3 前必须显式清除继承的非空 profile；H3 不支持此模板，不回退 H2。

```yaml
type: vless
tls: true
client-fingerprint: chrome
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

## 四模板边界

模板由 fork 固定密码套件、组/share、签名算法、扩展排列及受限扩展编码。

| 模板 | 主要差异 |
| --- | --- |
| Chrome120 | 经典 X25519 share，GREASE/乱序、ECH GREASE、Brotli、条件 padding、旧 ALPS 17513 |
| Chrome133 | 普通 TLS 使用原生 X25519MLKEM768 和 X25519 双 share；新 ALPS 17613，无 padding |
| Firefox120 | 自有 cipher 顺序、固定扩展顺序、X25519/P-256 双 share，无 GREASE/ALPS/证书压缩 |
| Safari16.0 | 固定扩展和签名顺序、GREASE、条件 padding、真实 Zlib 解压，无 ECH/ALPS |

TLS 版本范围、SNI、ALPN、证书策略、身份和恢复预算仍由节点及传输决定。
因此名称表示版本固定的 TLS 模板，不承诺完整浏览器行为或所有上下文的逐字节相同。
最低 TLS1.2；Safari 的 TLS1.0/1.1 声明裁剪，Vision/XHTTP/REALITY 继续强制 TLS1.3。
ALPS 仅在实际提供 h2 时发送，不复制 Mihomo 某些 WS 调用中的额外 h2 ALPS。
classic REALITY 移除 Chrome133 的 ML-KEM group/share，并绑定实际 X25519 私钥；
Firefox 的额外经典 share 不产生第二份 REALITY 身份。REALITY 仍拒绝 HRR、恢复和 0-RTT。

Firefox 的 FFDHE、delegated credentials、record size limit 及 Safari 的模板专用
cipher 声明不开放新的配置能力；不能真实完成的对端选择明确失败，不静默换模板。

不模拟浏览器 HTTP/2 SETTINGS、QUIC 参数、实际 ECH 或混合后量子 REALITY。
当前 HTTP 驱动不导入 TLS ALPS 中的应用设置，因此**非空 ALPS 响应明确失败**；
未协商或协商空设置可用。Brotli/Zlib 解压输出和原生证书消息上限均为 128 KiB；
超限、截断、错误算法和损坏压缩流失败，不能绕过证书认证。

## 所有权与关闭

节点的 SNI、ALPN、验证策略、mTLS 身份、版本范围、profile 和 SSL 上下文不可变。
每次独立构造建立独立缓存，clone 只共享同一节点。标准 TLS 的运行时票据总预算为 4；
TLS 1.3 票据只消费一次，TLS 1.2 会话也计入预算，过期票据清除，零预算关闭恢复。
握手及应用层 ALPN 策略通过前，暂存票据不会进入节点缓存。REALITY 始终不恢复。
别名只复用模板，不扩大节点/下载腿缓存归属。冷连接和恢复连接分开验收；VCore 的
票据策略不同于 Mihomo，恢复 hello 不宣称逐字段相同，也不伪造 PSK/binder。

CloseWrite 刷新 close_notify 最多 5 秒，保留底层连接和读方向；重复关闭幂等，
关闭后拒绝写入。Vision direct 切换保留同一 TLS 记录边界，先排空明文/刷新密文，
不向裸流插入外层 TLS alert。XHTTP 仍按其整条逻辑连接关闭契约工作。

## 验证与发布

验证使用真实公开配置、共享连接接口和独占容器内的原生协议对端；
编解码及纯内存 TLS 测试不启动宿主监听器。命令见 [构建与检查](../scripts/README.md)，
当次执行范围见 [验收矩阵](acceptance.md)。设备、性能、体积和发布许可证审查各自独立，
本地互通或交叉编译不替代这些门禁。

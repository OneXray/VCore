# selected-v1：fork 库阶段与接线边界

2026-09-25。**CF0–CF3 完成；CF4 仅完成 fork 本地子包，完整阶段仍 IN PROGRESS；CF5 NOT RUN。**
本记录不修改 VCore 生产配置、schema19、Cargo.toml 或 Cargo.lock，也不提前开放七个公开值。

## 本地提交与证据归属

| 仓库 / 阶段 | 本地提交 | 实际证据 |
| --- | --- | --- |
| VCore / CF0 | `1d1aa4c` | 116 组官方参考采样、144 项离线测试，见 [CF0](CF0.md) |
| boring / CF1 | `11e6aba5` | 共享模板目录、Chrome120 回归，23 项组合测试 |
| boring / CF2 | `bcf7c9f7` | Chrome133、普通 TLS 原生 ML-KEM、新 ALPS、真实恢复，29 项组合测试 |
| boring / CF3 | `39b00c49` | Firefox120、Safari16.0、真实有界 Zlib、完整字段及可协商算法，38 项组合测试 |
| boring / CF4 fork 子包 | `e81c6837` | 四模板 classic REALITY 绑定、负例与回归，43 项组合测试 |

boring 分支为 `feat/client-fingerprint-selected`，本轮尚未 push。
可复现命令、具体边界、依赖与补丁 hash 分别保存在该仓库的
`docs/client-fingerprint-cf1.md`、`docs/client-fingerprint-cf2.md`、
`docs/client-fingerprint-cf3.md`、`docs/client-fingerprint-cf4-fork.md`。
这些提交是库级来源记录，不是已发布的生产依赖 revision。

## 新子包验证范围

- Firefox 保留双经典 share 和固定字段；Safari 使用真实 Zlib，明确 TLS1.2 下限、
  冷连接 ticket、重复签名算法和 template-only 声明边界。声明但不支持的选择有拒绝用例。
- classic REALITY 只移除 Chrome133 的 ML-KEM group/share；普通 TLS 保留 ML-KEM。
  认证查找真正的 X25519 对象，不依赖 share 排序，也不强制丢弃 Firefox 的 P-256。
- 完整 wire 字段通过独立参考字面向量检查；内存对端完成真实 TLS 和请求响应。
  四模板覆盖临时证书 HMAC / CertificateVerify、低阶点、重复封装、TLS1.2 / HRR、
  PQ share / early data 拒绝。为让普通原生服务端参与，REALITY 密码学内存 fixture
  单独追加 Ed25519 声明；完整 wire fixture 不追加，不能把前者称为原样模板互通。
- 无服务端在宿主监听。默认/feature-off、指纹独立 feature、REALITY 独立 feature、
  定向 Clippy、fmt 和 diff 检查分别通过；不继承历史容器、设备或平台构建成绩。

`selected-v1.json` 中 CF2/CF3 的六个库测试入口现在已实现，移除对应 planned 标记。
清单依旧是门禁声明，不是运行结果；不因此改变任何 VCore 业务用例的待验状态。

## 下一执行边界

需要先获准将上述 boring 分支 push 到其 origin，发布可获取的不可变 revision。
随后 VCore 才能一起更新 Git 依赖 / lockfile，接入七值、下载腿规则及 schema20，
执行新的隔离 Mihomo 数据面和安全互通。发布前不提交无法获取的依赖，不使用相邻
path 依赖替代交付。CF4 完整签收、CF5 传输/生命周期/平台验收仍未完成。

## 后续发布记录

用户随后批准 push；远端功能分支已确认 `e81c6837a302241d81c0930610b4f34dd4328167`。
以上段落保留发布前的证据边界；后续 VCore 依赖/配置和业务验证见 [CF4 接线记录](CF4.md)，
不将发布本身计为协议互通通过。

# GeoData rules

状态：当前公共契约。VCore 管理 `dataDir/geodata` 下的 `geosite.dat` 和 `geoip.dat`，按当前公共实例的实际需求加载有界 matcher。资产缺失或更新失败按种类降级，不阻塞首次启动；配置、资产格式或资源边界错误继续 fail closed。

## 1. 规则

```yaml
rules:
  - GEOSITE,category-ads-all,REJECT
  - GEOSITE,cn,DIRECT
  - GEOIP,PRIVATE,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,vless-edge
```

语法：

```text
GEOSITE,<code>,<target>
GEOIP,<code>,<target>[,no-resolve]
```

- rule type 与 `code` 不区分 ASCII 大小写；proxy target 大小写敏感。
- `target` 只能是 `DIRECT`、`REJECT` 或实际 proxy name。
- `code` 必须匹配 `[A-Za-z0-9][A-Za-z0-9._+!-]{0,63}`，按 ASCII case-fold 判重。
- `GEOSITE` 恰好三段；`GEOIP` 只允许可选、大小写敏感的 `no-resolve`。
- 不支持反选、attribute selector、一条规则多个 code、source GeoIP 或隐式 LAN 分类。
- 规则按顺序首条命中；最终 `MATCH` 仍必须指向实际 proxy name。

DNS `nameserver-policy` 中的 `geosite:<code>[,<code>...]` 与业务规则共享同一需求集合和 matcher。

## 2. 资产

| 规则 | 文件 | 顶层消息 | 内容 |
| --- | --- | --- | --- |
| `GEOSITE` | `geosite.dat` | `GeoSiteList` | code 与 Domain records |
| `GEOIP` | `geoip.dat` | `GeoIPList` | code 与 IPv4/IPv6 CIDR |

VCore 只接受当前实现支持的 protobuf wire 子集：

- 固定文件位于 `dataDir/geodata`，YAML 不能指定本地路径或环境变量。
- 文件必须是普通文件；outer framing、code、引用分类、CIDR、Regex 和资源上限全部校验。
- 第一遍只建立 code 到文件范围的有界索引；未选分类按长度跳过。第二遍只解析被引用分类。
- 目标 code 在可用资产中缺失、重复或损坏时，该种资产快照不可用；不能伪装成空分类。
- GeoSite 与 GeoIP 独立：一类不可用不影响另一类和基础规则。

可选更新配置必须全有或全无：

```yaml
geox-url:
  geoip: https://assets.example.com/geoip.dat
  geosite: https://assets.example.com/geosite.dat
geo-auto-update: true
geo-update-interval: 24
```

约束：

- `geox-url` 只能含 `geoip` 和 `geosite`；URL 必须是 domain host、无 userinfo/fragment 的绝对 HTTPS URL。
- `geo-update-interval` 当前只接受整数 `24`。
- `validateConfig` 和 `prepare` 不下载；只有实例已经 `start`、auto-update 为 true 且实际需要对应资产时才启动后台任务。
- 下载固定使用最终 `MATCH` proxy graph，不允许 DIRECT 或 system-proxy fallback。
- 缺失资产立即安排检查；失败按 1 分钟、5 分钟、15 分钟、1 小时退避，之后保持 1 小时上限。成功检查恢复 24 小时周期。
- ETag、SHA-256、source URL 和下一次检查时间保存在 VCore 管理的 state 中。合法 304 只推进调度，不重写资产。
- 下载先写同目录 staging 文件，完成大小、hash、wire、需求和资源校验后原子替换。失败保留上一份有效资产。
- 跨进程 update lock、原子 rename 和崩溃恢复只保护共享数据目录，不构成多实例调度协议。

## 3. GeoSite 匹配

路由 domain 的来源优先级为：

```text
sniffed domain > TUN DNS hint > destination domain > no domain
```

Sniffer 和 DNS hint 只参与选路，不改写实际 outbound destination。没有 domain 时 `GEOSITE` 不匹配，也不触发正向或反向 DNS。

Domain 规范化：

1. 移除一个末尾点。
2. 使用 UTS #46 non-transitional + STD3 生成 ASCII A-label。
3. 转为 ASCII 小写。
4. 若 IDNA 处理失败，只允许严格的 1–253 byte opaque ASCII DNS name fallback；每个 label 为 1–63 byte，只含字母、数字和内部连字符。

两条路径都失败时拒绝该 session/datagram。规范化结果写入有界 routing context，后续规则复用。

支持四种 Domain record：

| 类型 | 语义 |
| --- | --- |
| `Plain` / `Substr` | 完整 domain 包含 value |
| `Domain` | 等于 value 或属于其子域 |
| `Full` | 完全相等 |
| `Regex` | 在规范化后的完整 ASCII domain 上执行 search |

Regex 只接受有界 ASCII source 和 RE2-class 子集；不支持 look-around、backreference 或额外 inline mode。每条 Regex 独立编译为 dense DFA，关闭 accelerator，并同时受 source、编译预留和 retained-memory 上限约束。运行期匹配不分配堆内存。

## 4. GeoIP 与 `no-resolve`

- 已有目标 IP 时直接匹配同地址族 CIDR；`no-resolve` 不改变结果。
- 只有 domain、尚无 IP 且当前规则带 `no-resolve` 时，不触发 DNS并继续后续规则。
- 后续不带 `no-resolve` 的 IP 类规则最多触发一次 runtime DNS；结果只供当前规则及其后的规则复用，不回溯先前规则。
- A 结果先于 AAAA；第一个命中 CIDR 的有效地址成为该 session/datagram 的固定目标。
- `dns.ipv6: false` 时不请求或采用 AAAA。
- runtime DNS 不可用或失败时继续下一条规则；不得改用 bootstrap resolver。
- `GEOIP` 不执行反向 DNS，也不接受 `reverse_match`。

## 5. 生命周期

- `validateConfig` 只校验 schema、URL 组合、code、去重和引用上限，不读取磁盘或联网。
- `prepare` 注册去重后的需求并读取当时可用的本地快照，不等待更新。
- manager 只为当前公共实例构建 matcher；停止或销毁实例时释放需求和快照。
- 后台更新通过完整校验后原子发布不可变快照。后续新 flow 使用新快照；已经完成的路由决策不回溯。
- `measureDelay` 使用 node-only schema，不注册 GeoData、matcher 或 updater。

## 6. 资源上限

| 项目 | 上限 |
| --- | ---: |
| `geosite.dat` | 16 MiB |
| `geoip.dat` | 32 MiB |
| 每文件顶层分类 | 4,096 |
| 每实例 GeoSite + GeoIP 唯一 code | 16 |
| 选中 GeoSite Domain records | 65,536 |
| GeoSite value 总字节 | 2 MiB |
| Regex records / source 总量 | 512 / 64 KiB |
| 原始 CIDR records | 320,000 |
| GeoData allocation capacity | 8 MiB |
| Regex retained matcher | 512 KiB |
| 单 Regex 编译预留 | 最多 3 MiB且不超过剩余预算 |

每次扩容前执行 checked arithmetic 和同一 allocation ledger 检查。CIDR 可删除重复、删除被覆盖前缀并无损合并对齐 sibling；原始记录数上限在压缩前执行。预算统计 I/O scratch、索引、规范化临时区、matcher capacity 和 DFA retained memory。

## 7. 失败语义与验收

- 非法规则、URL 组合、code 或资源超限使配置校验失败。
- 磁盘缺失、损坏、下载失败或检查超时不使实例生命周期失败；该种资产保持 unavailable 或继续使用上一份有效快照。
- 不可用 GeoIP 规则不得触发惰性 DNS。
- state 损坏时在 update lock 下重置调度状态；另一个进程异常退出后的 stale updating 状态在锁释放后恢复。
- Host tests 覆盖 Domain/CIDR/Regex、规范化、资源预算、损坏资产、热切换、更新锁和原子提交。
- 物理 TUN、公网更新、接近文件上限的扫描时间和 Release iOS 整进程 footprint 仍需单独登记。

当前执行证据见 [`acceptance.md`](acceptance.md)。

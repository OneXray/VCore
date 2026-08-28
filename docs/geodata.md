# GeoData 规则与资产

VCore 管理 `dataDir/geodata` 下的 `geosite.dat` 和 `geoip.dat`，只为当前配置实际引用的分类构建有界匹配器。资产缺失或更新失败时，对应种类暂时不可用；配置错误、资产格式错误和资源越界仍然失败关闭。

## 规则

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

- 规则类型和 `code` 不区分 ASCII 大小写，代理目标名称大小写敏感。
- `target` 只能是 `DIRECT`、`REJECT` 或实际代理名。
- `code` 必须匹配 `[A-Za-z0-9][A-Za-z0-9._+!-]{0,63}`，按 ASCII 大小写折叠后判重。
- `GEOSITE` 恰好三段；`GEOIP` 只允许可选且大小写敏感的 `no-resolve`。
- 不支持反选、属性选择器、单条规则多个 code、源地址 GeoIP 或隐式局域网分类。
- 规则按顺序首条命中，最终 `MATCH` 必须指向实际代理。

DNS `nameserver-policy` 中的 `geosite:<code>[,<code>...]` 与业务规则共享同一份分类需求和匹配器。

## 资产格式

| 规则 | 文件 | 顶层消息 | 内容 |
| --- | --- | --- | --- |
| `GEOSITE` | `geosite.dat` | `GeoSiteList` | code 与 Domain 记录 |
| `GEOIP` | `geoip.dat` | `GeoIPList` | code 与 IPv4/IPv6 CIDR |

- 文件路径固定，YAML 不能指定本地路径或环境变量。
- 文件必须是普通文件；外层帧、code、分类引用、CIDR、正则表达式和资源上限全部校验。
- 第一遍扫描只建立 code 到文件范围的有界索引；第二遍只解析被配置引用的分类。
- 目标 code 缺失、重复或损坏时，整份对应种类的快照不可用，不能当作空分类。
- GeoSite 和 GeoIP 相互独立，一类不可用不影响另一类和基础规则。

## 自动更新

更新配置必须整体出现或整体省略：

```yaml
geox-url:
  geoip: https://assets.example.com/geoip.dat
  geosite: https://assets.example.com/geosite.dat
geo-auto-update: true
geo-update-interval: 24
```

约束：

- `geox-url` 只能包含 `geoip` 和 `geosite`；URL 必须是以域名为主机、无 userinfo/fragment 的绝对 HTTPS URL。
- `geo-update-interval` 只接受整数 `24`。
- `validateConfig` 和 `prepare` 不下载。实例启动后，只有自动更新已开启且规则实际需要资产时才运行更新任务。
- 下载固定使用最终 `MATCH` 选中的完整代理链，不回退 DIRECT 或系统代理。
- 缺失资产立即检查；失败后按 1 分钟、5 分钟、15 分钟、1 小时退避，之后保持 1 小时上限。成功后恢复 24 小时周期。
- ETag、SHA-256、源 URL 和下次检查时间保存在 VCore 管理的状态中。合法 304 只推进调度。
- 下载写入同目录暂存文件，通过大小、hash、wire、需求和资源校验后原子替换。失败保留上一份有效资产。
- 跨进程更新锁和原子重命名只保护共享数据目录，不提供多实例调度协议。

## GeoSite 匹配

选路域名来源的优先级为：

```text
嗅探域名 > TUN DNS 提示 > 目标域名 > 无域名
```

嗅探和 DNS 提示只参与选路，不改写实际出站目标。没有域名时，`GEOSITE` 不匹配，也不触发 DNS。

域名规范化：

1. 移除一个末尾点；
2. 使用 UTS #46 non-transitional 和 STD3 生成 ASCII A-label；
3. 转为 ASCII 小写；
4. IDNA 失败时，只允许严格的 1–253 字节 ASCII DNS 名称，每个 label 为 1–63 字节且只含字母、数字和内部连字符。

两条路径都失败时拒绝当前会话或数据报。规范化结果写入有界选路上下文供后续规则复用。

支持的 Domain 记录：

| 类型 | 语义 |
| --- | --- |
| `Plain` / `Substr` | 完整域名包含 value |
| `Domain` | 等于 value 或属于其子域 |
| `Full` | 完全相等 |
| `Regex` | 在规范化后的完整 ASCII 域名上执行搜索 |

`Regex` 只接受有界 ASCII 源和 RE2 类子集，不支持 look-around、backreference 或额外内联模式。每条正则独立编译为 dense DFA，关闭 accelerator，并同时受源码、编译预留和保留内存上限约束；运行期匹配不分配堆内存。

## GeoIP 与 `no-resolve`

- 目标已经是 IP 时直接匹配同地址族 CIDR，`no-resolve` 不改变结果。
- 目标只有域名且规则带 `no-resolve` 时，不触发 DNS，继续后续规则。
- 之后首条不带 `no-resolve` 的 IP 类规则最多触发一次运行时 DNS，结果只供当前和后续规则复用。
- A 结果先于 AAAA；第一个命中 CIDR 的有效地址成为当前会话或数据报的固定目标。
- `dns.ipv6: false` 时不请求或采用 AAAA。
- 运行时 DNS 不可用或失败时继续下一条规则，不使用引导解析器替代。
- `GEOIP` 不执行反向 DNS，也不接受 `reverse_match`。

## 生命周期

- `validateConfig` 只校验结构、URL、code、去重和引用上限，不读磁盘、不联网。
- `prepare` 注册去重后的需求并读取当时可用的本地快照，不等待更新。
- Manager 只为当前公共实例构建匹配器；停止或销毁实例时释放需求和快照。
- 后台更新通过完整校验后原子发布不可变快照。新流使用新快照，已经完成的选路不回溯。
- `measureDelay` 不注册 GeoData、匹配器或更新任务。

## 资源上限

| 项目 | 上限 |
| --- | ---: |
| `geosite.dat` | 16 MiB |
| `geoip.dat` | 32 MiB |
| 每文件顶层分类 | 4,096 |
| 每实例 GeoSite + GeoIP 唯一 code | 16 |
| 选中 GeoSite Domain 记录 | 65,536 |
| GeoSite value 总字节 | 2 MiB |
| Regex 记录 / 源码总量 | 512 / 64 KiB |
| 原始 CIDR 记录 | 320,000 |
| GeoData 分配容量 | 8 MiB |
| Regex 保留内存 | 512 KiB |
| 单条 Regex 编译预留 | 最多 3 MiB，且不超过剩余预算 |

每次扩容前执行 checked arithmetic 和同一分配账本检查。CIDR 可以去重、删除被覆盖前缀并无损合并对齐 sibling；原始记录数在压缩前检查。预算包括 I/O 暂存区、索引、规范化临时区、匹配器容量和 DFA 保留内存。

## 失败语义

- 非法规则、URL 组合、code 或资源越界使配置校验失败。
- 文件缺失、损坏、下载失败或检查超时不使实例生命周期失败；对应资产保持不可用或继续使用上一份有效快照。
- 不可用的 GeoIP 规则不得触发惰性 DNS。
- 调度状态损坏时在更新锁内重置；异常退出留下的更新状态在锁释放后恢复。

自动化与实机覆盖范围见 [验收矩阵](acceptance.md)。

# GeoData 规则与资产

VCore 管理 `dataDir/geodata` 下的 `geosite.dat` 和 `geoip.dat`，只为当前配置实际引用的分类构建匹配器，不设 GeoData 数量上限或内存预算。资产缺失或更新失败时，对应种类暂时不可用；配置、格式、整数表示和可恢复分配错误仍然失败关闭。

## 规则

```yaml
rules:
  - GEOSITE,category-ads-all,REJECT
  - GEOSITE,cn,DIRECT
  - GEOIP,PRIVATE,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,main-select
```

语法：

```text
GEOSITE,<code>,<target>
GEOIP,<code>,<target>[,no-resolve]
```

- 规则类型和 `code` 不区分 ASCII 大小写，route target 名称大小写敏感并精确匹配。
- `target` 只能是 `DIRECT`、`REJECT`、实际代理节点名或静态 `select` 组名。
- `code` 必须匹配 `[A-Za-z0-9][A-Za-z0-9._+!-]{0,63}`，按 ASCII 大小写折叠后判重。
- `GEOSITE` 恰好三段；`GEOIP` 只允许可选且大小写敏感的 `no-resolve`。
- 不支持反选、属性选择器、单条规则多个 code、源地址 GeoIP 或隐式局域网分类。
- 规则按顺序首条命中，最终 `MATCH` 必须指向实际代理节点或代理组。

DNS `nameserver-policy` 中的 `geosite:<code>[,<code>...]` 与业务规则共享同一份分类需求和匹配器。

## 资产格式

| 规则 | 文件 | 顶层消息 | 内容 |
| --- | --- | --- | --- |
| `GEOSITE` | `geosite.dat` | `GeoSiteList` | code 与 Domain 记录 |
| `GEOIP` | `geoip.dat` | `GeoIPList` | code 与 IPv4/IPv6 CIDR |

- 文件路径固定，YAML 不能指定本地路径或环境变量。
- 文件必须是普通文件；外层帧、code、分类引用、CIDR 和正则表达式全部校验。
- 第一遍扫描建立 code 到文件范围的索引，容量按需增长；第二遍只解析被配置引用的分类。
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
- 下载固定使用最终 `MATCH` route target。若它是代理组，每次新建下载物理 transport 时沿嵌套组解析到当时选中的具体节点、`DIRECT` 或 `REJECT`；失败不自动换成员，也不隐式回退 DIRECT 或系统代理。
- 缺失资产立即检查；失败后按 1 分钟、5 分钟、15 分钟、1 小时退避，之后保持 1 小时上限。成功后恢复 24 小时周期。
- ETag、SHA-256、源 URL 和下次检查时间保存在 VCore 管理的状态中。合法 304 只推进调度。
- 下载以固定大小缓冲流式写入同目录暂存文件，不限制资产总字节；保留 90 秒期限、取消、HTTPS/HTTP 解析边界和字节计数溢出检查。文件大小必须与下载报告一致，通过 wire 和分类需求校验后原子替换，SHA-256 随状态保存；失败保留上一份有效资产。
- 跨进程更新锁和原子重命名只保护共享数据目录，不提供多实例调度协议。

隔离实验可显式编译独立、非默认 `benchmark-geodata-http` feature，使 GeoData 更新
接受以域名为主机、无 userinfo/fragment 的 HTTP fixture；仍通过同一个 dispatcher 和
流式下载器，不建立 TLS。HTTP 重定向可保持 HTTP 或升级到 HTTPS，HTTPS 不允许降级。
该入口没有环境变量或新的 YAML/FFI 开关；未编译该 feature 时仍强制 HTTPS，HTTPS 的
公开根和完整证书验证不变。平台构建及 delivery 拒绝该测试 feature。HTTP 实验只验收
更新逻辑与资源占用，不构成生产 HTTPS 信任链验收，不应启用 `interop-test`。

## GeoSite 匹配

TUN 的 IP 目标采用以下选路提示优先级：

```text
嗅探域名 > TUN DNS 提示 > 无域名
```

目标本来是域名时使用目标域名，不受提示覆盖。嗅探和 DNS 提示只参与选路，不改写
实际出站目标。没有域名时，`GEOSITE` 不匹配，也不触发 DNS。

运行时目标、嗅探和 DNS 提示的域名规范化（不是资产加载条件）：

1. 移除一个末尾点；
2. 使用 UTS #46 non-transitional 和 STD3 生成 ASCII A-label；
3. 转为 ASCII 小写；
4. IDNA 失败时，只允许严格的 1–253 字节 ASCII DNS 名称，每个 label 为 1–63 字节且只含字母、数字和内部连字符。

目标域名两条路径都失败时拒绝当前会话或数据报；IP 目标的嗅探/DNS 提示则是尽力注解，
无法规范化时忽略提示，不使合法 IP 目标不可达。规范化结果写入有界选路上下文供后续规则复用。

资产中的 `Domain` / `Full` 是静态字面匹配值，不是将要解析的 DNS 主机名，不再以
STD3、LDH 字符、63/253 字节或合法 Punycode 作为加载条件。移除一个末尾点、转小写；
ASCII 值直接处理，不为每条记录分配规范化字符串。Unicode 值尽可能转换为 ASCII
A-label，保持现有 IDN 匹配；转换失败则保留小写 UTF-8 字面值，不丢弃记录，也不使
整个分类失效。引号、下划线、反斜杠等字符不擅自删除，`*` 不新增通配语义。

仍要求记录字段、类型、UTF-8 与规范化后的非空值合法，保留整数与 arena 表示边界。
这些静态值不会直接传入 DNS、TLS 或连接接口；能加载不代表每个值都能成为合法的
运行时目标。实际目标的现有规范化、DNS wire 长度检查和 TLS 身份验证不受此调整影响。
Mihomo 也不以严格 DNS 主机名语法校验 GeoSite 值；其 Unicode/尾点模式行为不同，
本次保留 VCore 现有的合法 IDN 和单尾点规范化，不宣称所有模式语义完全一致。

支持的 Domain 记录：

| 类型 | 语义 |
| --- | --- |
| `Plain` / `Substr` | 完整域名包含 value |
| `Domain` | 等于 value 或属于其子域 |
| `Full` | 完全相等 |
| `Regex` | 在规范化后的完整 ASCII 域名上执行搜索 |

Domain/Full 在加载时原地排序紧凑记录，运行时对完整名称及逐 label 后缀做二分查找，
未命中也不线性遍历全部 Domain/Full，不复制 value arena。Substr
与 Regex 仍按各自语义匹配，分类内各记录是集合并集，不影响外层规则的首命中顺序。

`Regex` 只接受 ASCII 源和 RE2 类子集，不支持 look-around、backreference 或额外内联模式。每条正则独立编译为 dense DFA，关闭 accelerator；不设置记录数、累计源码、NFA/DFA 编译或保留内存预算。库自身的合法语法、嵌套深度与状态/索引可表示性检查仍有效；运行期匹配不分配堆内存。复杂正则可能显著增加编译耗时和峰值，不能由“运行期不分配”推导加载期内存有界。

## GeoIP 与 `no-resolve`

- 目标已经是 IP 时直接匹配同地址族 CIDR，`no-resolve` 不改变结果。
- 目标只有域名且规则带 `no-resolve` 时，不触发 DNS，继续后续规则。
- 之后首条不带 `no-resolve` 的 IP 类规则最多触发一次运行时 DNS，结果只供当前和后续规则复用。
- A 结果先于 AAAA；第一个命中 CIDR 的有效地址成为当前会话或数据报的固定目标。
- `dns.ipv6: false` 时不请求或采用 AAAA。
- 运行时 DNS 不可用或失败时继续下一条规则，不使用引导解析器替代。
- `GEOIP` 不执行反向 DNS，也不接受 `reverse_match`。

## 生命周期

- `validateConfig` 只校验结构、URL、code 和去重，不读磁盘、不联网；不限制 GeoData 唯一引用数或 GeoSite DNS policy 数。
- `prepare` 注册去重后的需求并读取当时可用的本地快照，不等待更新。
- Manager 只为当前公共实例构建匹配器；停止或销毁实例时释放需求和快照。
- 后台更新通过完整校验后原子发布不可变快照。新流使用新快照，已经完成的选路不回溯。
- 分类表在加载时按 code 排序，运行时大小写无关二分定位；规则仍按配置顺序首命中。
  每次业务选路捕获一份当前不可变快照，整次求值复用，不在每条 Geo 规则上重复读取 ArcSwap。
- TUN UDP 的 IP 目标按五元组固定 action；源地址/端口、UDP 和入口由源关联固定，
  关联内按目的 IP/端口独立记录。首包完成嗅探与选路后，活动流不再逐包读取 DNS
  提示或匹配规则，DNS/GeoData 更新只影响新流。状态仅保留 action、活动时间和
  可选的已认证 QUIC 连接标识，不持有域名、DNS 答案或 GeoData 快照。
- 已启用的 QUIC 嗅探端口中，同五元组出现新认证 Initial 时重新选路；同标识重传、短头、未认证候选和
  不支持版本不使既有流重新选路。每目的 30 秒空闲失效，10 秒间隔在关联活动时
  回收，完全空闲的源仍由既有关联清理回收；不创建逐流任务、队列或 socket。
- 显式域名目标和非 TUN UDP 继续逐包选路/解析，不把域名冻结为旧 DNS 答案。
  固定 action 不是固定代理组叶子：同源关联仍复用每 route target 的物理 transport，
  已有 transport 保持原成员，只有新建物理 transport 读取新的组选择。
  相比 Mihomo 的按源关联首包选路，本实现细分到五元组，不宣称两者完全同义。
- Controller 切换代理组不会重启正在进行的下载或迁移既有连接；只有之后新建的 GeoData 下载物理 transport 使用新选择。
- `measureDelay` 不注册 GeoData、匹配器或更新任务。

## 内存与安全边界

分类数、唯一引用数、Domain/Regex/CIDR 记录数、累计 value/Regex 源码字节、资产文件
大小以及加载/正则内存均不设置固定额度。没有按平台隐藏恢复的 GeoData 配额，也不
截断规则或换较小分类。普通 YAML 256 KiB、显式 rules 1,024 条/合计 128 KiB/单条
1 KiB 是另外的配置入口边界，不是资产内记录数上限，当前保持不变。

保留 checked arithmetic、fallible Vec 扩容、合法 protobuf 帧/长度、code、匹配值的
UTF-8 与非空检查、CIDR 地址宽度/前缀和正则语法检查。紧凑 value/Regex arena 的 offset/length 仍须
能表示为 u32；这是存储表示边界，不是可配置的内存预算。CIDR 仍无损去重、删除被覆盖
前缀并合并对齐 sibling。分配失败可能返回错误；系统 OOM 或第三方不可恢复分配失败
不保证可恢复。

容量账本仅作诊断：统计 matcher/index/临时 Vec 和保留 DFA，扩容时记录新旧缓冲
可能重叠的容量；没有最大值、不控制准入。**不包含正则编译器全部临时分配、配置需求
集合、allocator 开销或整个进程 footprint**，其 accounted peak 不是加载峰值上界。
50,000,000 bytes 是限定输入与联合负载下的进程实测验收目标，不是加载器保证。

完整官方 CN / Russia 所选分类的压力测试由独立 `container-benchmark` 工程提供，
以 `--vcore` 显式指定被测 checkout。生产 ABI 进程加载两类完整资产，经少量命中/未命中见证和实际 fd-TUN
负载观察选路及全生命周期内存峰值；不逐条穷举规则语义。仅 prepare 成功或离线记录数
统计不能证明实际转发路径已经运行。

## 失败语义

- 非法规则、URL 组合、code 或通用配置入口越界使配置校验失败。
- 文件缺失、损坏、下载失败或检查超时不使实例生命周期失败；对应资产保持不可用或继续使用上一份有效快照。
- 不可用的 GeoIP 规则不得触发惰性 DNS。
- 调度状态损坏时在更新锁内重置；异常退出留下的更新状态在锁释放后恢复。

自动化与实机覆盖范围见 [验收矩阵](acceptance.md)。

# 测试入口

本仓库保留生产核心的配置、内存 IO、安全和生命周期回归，直接以定向 Rust 测试
执行。[VCore scripts](../scripts/README.md) 只编译核心与平台产物。协议互通、对端
下载、容器消费者以及内存/吞吐压力由独立的 [container-benchmark](https://github.com/YuanDevTeam/container-benchmark)
维护，通过显式 VCore checkout 指定被测核心；编译不依赖 benchmark 的安装或路径。

| 层次 | 保留内容 | 入口 |
| --- | --- | --- |
| 核心回归 | 严格配置、协议/TLS 内存 IO、局部上限、取消、Invoke/原生传输边界和确定性回归 | 定向 cargo test |
| 编译 | 精简 feature、生产 feature、平台架构与全目标编译 | VCore scripts build |
| 编译工具回归 | 平台构建、产物身份与构建参数回归 | scripts/tests |
| 协议互通 | 官方 listener、生产 ABI 消费者、TCP/UDP 内容与代理路径 | 独立 container-benchmark interop |
| 性能评估 | Linux 原生 TUN、完整 CN 分流、吞吐/CPU/RSS/UDP 丢包/DNS | 独立 container-benchmark compare |
| 内存压力 | 完整真实 CN GeoData、加载与联合流量下的进程峰值 | 独立 container-benchmark stress |

在独立 benchmark 工程中执行，`PATH` 为显式 VCore checkout：

```sh
container-benchmark interop --source vcore=PATH
container-benchmark stress --source vcore=PATH
```

`interop --list` 可不提供 source，只列出测试，不运行互通。

所有服务端遵守[隔离规则](../docs/testing-isolation.md)。定向核心回归只运行不启服务的
内存用例；全目标测试编译使用 `--no-run`，ignored 不算通过。物理设备和正式安装
不由本地测试或 Linux 内存压力推导。

## CI 构建策略

CI 同时运行 Debug 和 Release 语义的纯内存用例，测试目标与明确的过滤清单保持相同。
后者使用 `cargo test --profile ci-release`：继承 Release 的 `opt-level=3` 等设置，
仅关闭 LTO 并使用 16 个 codegen units，避免为每个测试二进制重复昂贵的优化链接。
它不等同于运行正式发布产物；平台交付仍使用未修改的 `release` 配置和身份检查。

Quality 保留生产 Clippy、精简 feature 的编译/实际准入测试和全部目标的编译检查，
完整生产 Release 构建由必跑的平台矩阵覆盖，不在 Quality 中重复执行。
Rust 依赖缓存区分检查种类、工具链、锁文件和 runner 镜像/SDK；命中后仍执行验证，
不缓存交付目录或复用已发布的核心产物。同一 PR 的新提交自动取消旧 CI，main 运行不主动取消。

## 必要回归与独立输入

- CLI：`cargo test --locked --no-default-features --features cli --bin vcore cli::tests::`
  覆盖五个参数的 Go flag 语法、优先级、原始路径/空值请求转换、未知参数脱敏、无损路径元数据、
  响应输出流和退出码。路径、环境默认、文件读取和信号属于共享 Invoke，不能由 CLI 另行实现。
  `cargo test --locked --no-default-features --features cli --lib invoke::foreground::tests::`
  覆盖用户/XDG 默认、独立路径归属、普通文件/FIFO/读取上限、标准输入、原生字符路径、
  帮助无路径依赖、有效 TUN 与缺失 GeoData 的无初始化校验、失败脱敏、启动中信号仍等待
  worker，以及 stderr 上限和运行工作器日志继承；Unix 非 Unicode 字节文件的真实读写只在
  Linux 执行，其他 Unix 仍校验元数据往返。`runtime::shutdown_tests::` 覆盖取消后任务
  join 和核心错误保留，不启动宿主监听器。CLI 的完整生产 feature 通过独立 `cli` 编译，
  不能以 `ffi` 的隐式激活代替。发布 helper 的离线回归由 `scripts/tests/test_cli_release.py`
  执行；六目标 tag 工作流配置不等于已运行通过。

- Invoke：共享入口位于 `src/invoke/`，C ABI/JNI 只是传输层。无版本字段的请求可查询核心
  身份和 stopped 实例；精确响应对象、初始化幂等、缺失 method/payload 与未知字段拒绝由
  `invoke::tests::version_and_state_use_the_fixed_response_envelope`、
  `invoke::tests::initialize_is_idempotent_only_for_the_same_data_directory` 和
  `invoke::tests::envelope_and_payload_are_strict` 的精确纯内存过滤器覆盖。
  `invoke::tests::start_accepts_only_config_yaml_and_removed_prepare_is_unknown` 覆盖唯一
  `start(configYaml)` payload 与已删除方法/字段的拒绝。
  `invoke::tests::validate_config_does_not_change_instance_state`、
  `invoke::tests::validate_config_allows_referenced_geodata_assets_to_be_missing` 和
  `invoke::tests::concurrent_validate_config_calls_return_the_same_result` 覆盖无初始化、
  无状态改变与可并发校验；`invoke::tests::engine_completion_notifies_after_panic_and_join_reports_failure`
  覆盖完成通知和真实 join 错误。整个 `invoke::tests::` 含历史监听器 fixture，不能作为宿主
  执行过滤器；按上述精确名称选择纯内存测试。
- 混合入站：`cargo test --locked --lib inbound::mixed::tests::` 在纯内存中覆盖
  HTTP/SOCKS5 分流、首字节与流水业务保留、LAN 免认证、认证拒绝、共同握手期限和
  取消后的双向释放；`inbound::socks5::association::tests::` 覆盖 UDP 来源、代次和
  边界。真实 TCP/UDP 同端口绑定、启动回滚和 Stop 后端口释放在隔离容器中验证。
- Dialer 物理初始化：client-only TCP/UDP 的快速创建、64 个未完成提交、共享阻塞池
  占用、慢 protect 故障注入、调用方取消、Stop 等待和新作用域恢复。mock protect
  在 connect 前拒绝，不启动宿主 listener 或发送业务；有限负载回归不证明任意
  等待者数量有界、完整 TUN 压力或 Apple 真机内存。
- h2_stream_regression：完整 END_STREAM 后 RST 不丢响应，未完成响应仍报错。
- stream_foundations 与 sing-mux：延迟响应遵守原建链期限；确认建立后允许继续读取。
- stream_shutdown：gRPC/legacy H2/池化 gRPC 和 XHTTP H1/H2 先送完再关闭；
  Stop 可取消待写，XHTTP 关闭有一秒上限。
- xhttp_h3_shutdown：纯内存 QUIC 背压下上传完成屏障、延迟握手、一秒关闭上限和 Stop。
  测试对端取消并 join 后台任务，不把 QUIC 关闭保留期当作客户端关闭期限。
- shadowsocks_backpressure：三算法 Pending 重试长度、读先于写时 codec 刷新，
  以及官方服务端对空首包零 padding 的确定性拒绝。不修改官方库。
- hysteria2_packet_ids：完成后重用 16 位分片 ID，不误丢后续业务包。
- shadowtls_config/stream：严格 v3、原生签名/Finished、残留 cover、背压/flush、
  读取取消和关闭期限；不能由内存回归推导真实官方对端互通。
- uot_config、shadowsocks_uot 与共享 outbound::uot：仅 v2、首包/读取门控、
  三算法 u16 边界、收发预算、受控 DNS、取消和 Stop。codec 上限不代表对端容量。
- security_capabilities：公开配置经真实 SecurityClient 在主/下载腿产生实际混合 share。
- tuic_config/tuic_memory 与 outbound::tuic：严格 v5、TLS exporter、无 ACK、
  双 UDP wire、分片/重组、关联 ID 退役、窗口/credit、Heartbeat 和 Stop。
- httpupgrade_config/httpupgrade_memory：普通/fast-open、ED、严格 101、部分写、
  首包恰好一次及原期限；已建连接不受建链期限限制。
- GeoData：所有平台均无记录数上限、数量截断或总内存预算；超旧数量/文件额度的完整
  加载、整数溢出、缺失/损坏和原子快照。四种 Domain 类型的正/负匹配、属性 key 存在性
  （bool false/int 0）、多属性 AND、顺序/重复/空项归一、Unicode simple-fold、整 selector
  反选与字面 `@!cn`；缺失/未声明 selector 不变全匹配，有效空交集与无域名保持独立。
  GeoIP IPv4/IPv6 与 `!code`、DAT reverse_match 忽略；业务规则与 DNS policy 共享基础
  分类和记录，属性重叠不重复 value/Regex。
  `dns_policy_selection_is_consistent_across_snapshot_swaps` 覆盖 DNS policy 跨 selector/项
  复用一份不可变快照，旧代与空快照切换不改变本次选择；空快照仍按缺失回落，返回前释放，
  不跨上游 I/O 的 `await` 持有。属性筛选在 value 解析/Regex 编译前执行，
  未选中正则不编译。下载、文件结构和 staging 检查期间保留旧 matcher；构建新代前
  卸载旧代，等待既有读者完成及存储析构，新流仅跳过不可用 Geo 规则，普通规则与
  DNS 回落不变。卸载后的加载失败使坏种类不可用、健康另一类独立发布，旧磁盘资产
  保留；过期更新租约不能卸载新注册实例、写入资产或替换其快照。更新候选只构建一次，
  管理重载与提交串行。`status_recovers_external_generation_cancelled_before_unload`
  覆盖已缓存外部新代次、卸载前取消时保留旧 matcher 与待重载状态，后续未取消的
  状态观测无需新磁盘代次即可恢复。取消排空不迟发新候选；304 可用时只调度，不可用时重载本地。
  后台管理任务受 Stop 等待，CPU 加载结束检查取消；排空的取消检查间隔不构成整个
  Stop 时限。纯内存回归不替代真实自动更新叠加流量的压力验收。
  分类异序/大小写定位与重载保持独立；TUN UDP 五元组独立固定 action，提示/GeoData
  更新只影响新流并释放旧快照；认证 QUIC 连接标识变更、同标识重传、逐目标空闲回收
  与响应刷新保持独立。域名 DNS 答案和非 TUN 路径继续更新，已有组 transport 不迁移。
  真实 fd-TUN 联合流量、完整 CN 选择、合成四类型/复杂正则与更新期间峰值由独立 benchmark
  验证；输入身份、实测数据和证据边界见其 README。Regex 使用常规
  `regex::bytes::Regex`，保持 ASCII 语义与库默认编译/嵌套/缓存保护；所选正则编译
  失败使该种类不可用，不恢复旧整体快照。无 VCore 自设 NFA/DFA/determinization
  额度、正则条数或总内存预算。
  容量账本不含正则库内部状态或搜索 scratch；Regex 搜索可能分配，不报告其内存为零。
  旧 dense DFA 输入实验不能替代当前实现的回归与压力结果，单次特定输入的 RSS
  也不能扩展为任意输入的内存保证。
  不把少量选路见证当作逐条规则语义证明，Linux RSS 不替代 Apple 真机 footprint。
- TUN 配置：`config::tests::tun_config_` 覆盖六个 Mihomo 同名字段、MTU 0/省略=9000、
  UDP timeout 0/省略=300 秒、DNS 精确/通配目标与空列表，以及未知字段拒绝。
  `tun_runtime::tests::configured_` 和 `routing::dispatcher::tests::configured_` 纯内存覆盖
  配置 MTU 真正进入平台读写/UDP 返回预算、DNS 匹配进入 TCP/UDP 分流、association 与逐目的
  流的实际 idle 清理。netstack 的 `configured_jumbo_mtu_preserves_full_udp_packets_for_both_families`
  与 `configured_jumbo_mtu_reaches_tcp_mss_for_both_ip_families` 覆盖双族完整 9000 字节包、
  超限拒绝及 TCP MSS；Linux 配置 MTU 元数据比对用纯消息回归验证，真实设备仍在容器中验证。
- TUN UDP：reader 直接分流、慢关联隔离、TCP ingress Full 不阻塞 UDP/DNS；唯一 writer
  三通道公平/关闭/非法包隔离、平台接受前 DNS permit 生命周期、取消及关联/DNS 任务
  同步回收。纯 codec 的 MTU/族边界、TCP-only 与通用 endpoint 回归在 netstack 内。
- TUN 批次：首包等待后仅收已就绪包、最多 8 包、独立包边界、IPv6 策略及逐包流量、
  非法包邻居保留、EOF/取消前缀与不重放；Windows 队列/唤醒纯内存回归不替代设备验证。
  netstack 入站维护按有界批次摊薄，TCP 仍逐包 ingress；同目标端口 SYN 的流绑定、
  相邻 ICMP、输出满时未消费后缀及取消/关闭保持独立回归。
- Windows Wintun：`platform::windows_wintun_io::tests::` 用内存设备替身覆盖 256 包
  入站队列、非法包邻居、脱敏读写错误、reader 中断与 join、部分写前缀、ring 暂满
  只重试未接受包，以及取消后无后台写入。Invoke 的
  `invoke::tests::start_accepts_only_config_yaml_and_removed_prepare_is_unknown` 覆盖
  `start(configYaml)` 和旧 `tunFd`/`tunFraming` 字段拒绝，不创建真实设备。动态 MTU 及
  UWP 1400 上限分别由平台内存回归覆盖。Windows 目标编译与这些内存
  回归分别记录；外置 DLL、权限、实际适配器收发、宿主地址/DNS/路由及 Stop 后原生
  句柄释放仍需 Windows 设备验证。已有 WinRT VPN 包验收不能代替 Wintun 设备结果。
- 独立 ClientHello golden、Encryption 密码向量与 limits 输入保留，
  不能用待测实现生成期望或以声明清单替代行为。

历史宿主 listener fixture 只编译；实际网络互通只在独立 benchmark 的隔离容器中执行。
容器和实验生成文件在每轮结束后清理，仅保存脱敏文字结论。版本、源码/锁文件 hash、
命令、实测数据及清理结果必须写明；文字结论不能抵扣未经执行的设备或发布门禁。

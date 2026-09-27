# 测试入口

测试按验证目的维护，不按开发阶段累积副本。当前命令见 [scripts](../scripts/README.md)。

| 层次 | 保留内容 | 入口 |
| --- | --- | --- |
| 日常 | 严格配置、feature、协议/TLS 内存 IO、局部上限、取消、FFI 边界和确定性回归 | check core --profile debug/release |
| 构建 | 精简 feature、生产 feature、全目标编译 | check core --profile features |
| 工具 | 子进程/容器清理、下载、原始证据完整性、平台产物 | scripts/tests |
| 网络 | 公开消费者、真实原生认证/传输/UDP/上游和资源 | protocol-interop --suite … |
| 发布候选 | 有序两跳、故障/重建/长测、平台产物/ABI | integration suite 与平台构建 |

所有服务端遵守[隔离规则](../docs/testing-isolation.md)，包括原站和对照客户端入口。
默认测试命令不执行历史宿主 listener。全目标仅 --no-run；ignored 不算通过。
物理设备和正式安装不由本地测试推导。

## 必要回归与独立输入

- h2_stream_regression：完整 END_STREAM 后 RST 不丢响应，未完成响应仍报错。
- shadowsocks_backpressure：三算法 Pending 重试长度和 server-first，不修改官方库。
- hysteria2_packet_ids：完成后重用 16 位分片 ID，不误丢后续业务包。
- n7_security_capabilities：公开配置经真实 SecurityClient 在主/下载腿产生实际混合 share；
  不再重复测试 fork 的纯 API 准入。
- fingerprints/mihomo-selected-v1.json：官方独立 ClientHello golden，不从待测实现重新生成期望。
- protocols/encryption-crypto.json 及 Go 生成器：独立密码向量；许可证和来源必须保留。
- protocols/limits.json：实际常量、边界与越界行为；不另建一套产品配置。

## 保留而未自动执行的 fixture

anytls_interop、xray_interop、mihomo_interop 仍含会话复用计数、双向 HTTP/SOCKS5、
CONNECT 预读/Upgrade 等独有断言。保留这些 Rust 消费者用于迁移，不能把“其他 echo 通过”
当作已覆盖而删除。旧宿主启动入口不再开放，迁移前只编译，不计为当前容器验收。
协议容器消费者已覆盖其共享数据、安全、组快照和 Stop 路径。

其他 tests 中含宿主 listener 的旧 fixture 同样不在 core 白名单；新增网络断言放容器
suite，或在能真实覆盖行为时改为纯内存 IO。不要把宿主服务端改称 mock 绕过规则。

阶段实验、重复规划表和只测试 BLOCKED 文案的诊断已删除；原始记录在 Git 历史。
必要负例、资源归零/静默检查和尚未替代的独有断言不按行数裁剪。

# CF0：精选指纹基线

日期：2026-09-25。范围：`selected-v1`。结果：**CF0 DONE；生产能力未变**。
这是新范围的基线，不沿用旧 F5；CF1–CF5 尚未签收。

## 已验证结果

- 冻结 [七值、四模板及 41 组阶段门禁声明](../../../tests/fingerprints/selected-v1.json)。
  `planned_entrypoint` 保持 NOT RUN；声明与后续必需覆盖不等于测试通过。
- [八份独立官方 raw 向量与比较规则](../../../tests/fingerprints/README.md)入库；
  保留顺序、负载长度、GREASE 关联、ECH/padding 变体、ticket/binder 结构。
- 最终运行 `target/interop/runs/client-fingerprint-cf0-20260925-03`：
  **116/116 CAPTURED，116 个观察值，16 个 OpenSSL TLS-only 握手；
  BASELINE VERIFIED，source_unchanged=true，cleanup=true**。
- 前两轮 `...-01` / `...-02` 同样完整捕获并通过原始记录检查；golden 来自第一轮，
  后两轮使用保留基线作比较，没有重生成期望掩盖差异。
- macOS ARM64，Apple Container host-only、guest MTU1500。观察端和官方客户端入口
  全部容器化；最终 `container list` 为空，未改宿主网络或启动宿主服务。
- 最终采样后只新增一个 CLI 参数位置的离线回归及本记录，没有修改采样实现。
  Python 144 项、Ruff check/format、`git diff --check` 通过。

| 身份 | 实际值 |
| --- | --- |
| VCore 父提交 | `69085306c67581695d1f0b77a36b7996672d904f` |
| 采样源码树 SHA-256（含未提交文件） | `14d663221ba642da6633fc60282521c6fad7076e3330494602e9a9692dcdc76f` |
| Cargo.lock SHA-256 | `0e8526449ee20749723d9ad522b9720029cb99a8a89e4d348b91289b2508756d` |
| reference-results.json SHA-256 | `283e50ff9d428a5c894123613e1559eb1fd1e74850a34261ede13f8fd733b061` |
| 官方 latest Mihomo | `v1.19.31`，Linux ARM64，`ab405bad5beeeac8b003bb01f60f134f6df54471` |
| 二进制 SHA-256 | `1b315bc038d05f84ee86d232f3c3d2b020b5044e9b971bb8fe215b6e6a2148f3` |
| 归档 SHA-256 | `9e0f11afbf38426b8bd88fdc594678f8161c57eccb4e1b77acb12b493904f1d4` |
| 二进制实际 uTLS 依赖 | `github.com/metacubex/utls v1.8.7` |
| TLS 观察端 | OpenSSL `3.5.8 25 Aug 2026` |
| python:3-alpine 镜像 digest | `sha256:9e9fde4d32eedce0b661d9ab91e826b62dddf28e928c230ec55f1866cac66b01` |

复现（采样必须换全新目录；完整运行目录不入 Git）：

```sh
uv run --project scripts --locked python -m vcore_scripts.protocol_fingerprint_reference --list
uv run --project scripts --locked python -m vcore_scripts.protocol_fingerprint_reference --run-dir target/interop/runs/<fresh-run>
uv run --project scripts --locked python -m vcore_scripts.protocol_fingerprint_reference --check-run target/interop/runs/<reference-run>
uv run --project scripts --locked python -m unittest discover -s scripts/tests
uv run --project scripts --locked ruff check scripts
uv run --project scripts --locked ruff format --check scripts
git diff --check
```

## 结论与边界

别名映射符合冻结范围。Chrome133 包含 ML-KEM、新 ALPS 码点且没有 padding；
classic REALITY 去掉混合组/share。Firefox120 有 X25519/P-256 双 share、固定扩展
顺序和独立 ECH GREASE 形状。Safari16 保留重复签名算法、Zlib、旧版本声明和特定
cipher 顺序；VCore 后续按批准的 TLS1.2 下限裁剪版本。声明不证明原生协商能力。

WS 参考只提供 HTTP/1.1 ALPN，Chrome 却仍发送 h2 ALPS；VCore 保留调用方决定
ALPN、只有提供 h2 才发送 ALPS 的策略。有界会话恢复也是独立的既有 VCore 策略，
不能用这些 cold/后续采样代替真实恢复验收。

capture-only 端主动结束握手，TLS-only 端不解码 VLESS、HTTP 或 REALITY 身份。
本阶段**不证明 VCore 新模板、代理数据面、REALITY 认证或平台发布通过**。
生产仍仅支持 `chrome120`，schema19 / Invoke v5 未变；未 push、未创建 PR。

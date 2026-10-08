# 测试

核心配置、内存 I/O 和生命周期回归留在本仓库。网络互通与压力测试由
[container-benchmark](https://github.com/YuanDevTeam/container-benchmark) 管理。

## 本地检查

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-features --lib --bins -- -D warnings
cargo test --locked --all-features --all-targets --no-run
cargo test --locked --no-default-features --features cli --bin vole cli::tests::
cargo test --locked --no-default-features --features cli --lib invoke::foreground::tests::
cargo test --locked --lib config::tests::
cargo test --locked --lib geodata::tests::
cargo test --manifest-path crates/vole-netstack/Cargo.toml --all-targets
uv run --project scripts --locked python -m unittest discover -s scripts/tests
uv run --project scripts --locked ruff check scripts
uv run --project scripts --locked ruff format --check scripts
```

宿主只执行明确的纯内存过滤器；全目标使用 `--no-run`。
`invoke::tests::` 含监听器用例，不可整体在宿主执行；可执行过滤器以
[Tests workflow](../.github/workflows/test.yml) 为准。
协议独立向量见 [protocols](protocols/README.md)，ClientHello 输入见 [fingerprints](fingerprints/README.md)。

脚本测试保留平台文件输出、Windows 后端选择、Android ABI/runtime、Apple 切片、
真实归档读写和许可证收集。外部编译命令由夹具替代，原生编译由 CI 平台矩阵执行。
CI 的核心回归分别使用 Debug 和 `ci-release`；后者继承 Release 优化并关闭 LTO，
正式产物使用标准 `release`。Quality 负责格式、Clippy、feature 编译和依赖来源检查。

## 网络与压力

```sh
container-benchmark interop --source vole=/path/to/Vole
container-benchmark stress --source vole=/path/to/Vole
container-benchmark compare --source vole=/path/to/Vole
```

所有服务端遵守 [容器隔离规则](../docs/testing-isolation.md)。用例和测量参数由 benchmark
维护，结果记录在对应运行或 PR 中；[验收边界](../docs/acceptance.md) 区分编译、互通与设备验证。

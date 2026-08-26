# VCore Windows UWP VPN 最小集成

本示例演示如何把 VCore 的 `Windows.Networking.Vpn` Provider、每会话完全信任运行时和一个最小命令行前台打进同一个 MSIX，并通过 `VCoreWindowsVpnInvoke` 创建、连接、查询和停止系统 VPN。

> 这里的 “UWP” 指 Windows 的 UWP VPN Provider 模型。VCore **不支持纯 AppContainer 前台直接承载完整集成**：profile/snapshot 管理和 Session Host 激活必须由同包的完全信任进程执行。已有纯 UWP UI 时，应增加一个完全信任 broker；不要从 UWP UI 直接调用桥接接口。

## 最小架构

```text
VCoreUwpDemo.exe（完全信任前台）
  └─ VCoreWindowsVpnInvoke
       ├─ 发布不可变配置快照
       ├─ 创建/更新同包 VPN profile
       └─ 激活 SessionHost

vcore-windows-session-host.exe（每次连接一个完全信任进程）
  └─ 完整 VCore：netstack / DNS / rules / outbounds

vcore-windows-vpn-host.exe + vcore.dll（AppContainer Provider）
  └─ VpnChannel / routes / DNS assignment / packet buffers / physical network
```

前台退出不会停止 VPN。Provider 或 Session Host 退出、管道损坏、非法 frame 或物理网络变化会失败关闭当前 VPN。

## 文件

| 文件 | 用途 |
| --- | --- |
| `demo.cpp` | 最小完全信任宿主；读取 YAML，调用 revision-1 Windows bridge |
| `demo.yaml` | 无真实凭据的生命周期示例；把流量交给 `127.0.0.1:1080` SOCKS5 |
| `AppxManifest.xml.in` | 完整最小 MSIX manifest，包括 Provider、Session Host 和受限能力 |
| `build.ps1` | 构建三项 VCore 产物、编译 demo、打包、签名并可选安装 |

示例没有实现第二套 Provider、netstack、管道协议或 profile 管理代码；这些都由 VCore 现有产物提供。

## 前置条件

- Windows 10 20H2 build 19042 或更新版本；
- `uv`、Visual Studio C++ 工具和 Windows 10/11 SDK；
- Rust Windows MSVC target：`aarch64-pc-windows-msvc` 或 `x86_64-pc-windows-msvc`；
- 可用于目标 `Publisher` 的代码签名证书，并已由测试设备信任；
- 旁加载需要开发者模式或组织允许的安装策略；
- Store 发布需要正式 package identity、publisher、`networkingVpnProvider` 与 `runFullTrust` 审批。

工作区默认复用 `cert/OneVCore.Phase0.pfx`。脚本只读取并签名，不生成、导入或删除证书。独立使用 VCore 时，通过 `-PfxPath`、`-PfxPassword`、`-Publisher` 和 `-IdentityName` 传入自己的值。

## 构建与安装

在仓库根目录执行：

```powershell
powershell -ExecutionPolicy Bypass -File example/windows-uwp/build.ps1 `
  -Architecture arm64 `
  -Version 1.0.0.0 `
  -Install
```

x64 使用：

```powershell
powershell -ExecutionPolicy Bypass -File example/windows-uwp/build.ps1 `
  -Architecture x64 `
  -Version 1.0.0.0 `
  -Install
```

脚本默认通过 `uv run --project scripts --locked vcore-scripts build windows` 构建 VCore。已经生成当前架构产物时可以加 `-SkipVCoreBuild`。输出位于：

```text
dist/windows-uwp-demo/VCore.UwpDemo.Dev_<version>_<arch>.msix
```

更新已安装包前必须先停止 VPN，并把四段式 MSIX 版本提高。架构必须在 demo、`vcore.dll`、Provider Host、Session Host 和 manifest 中保持一致。

## 运行最小 demo

安装后重新打开终端，让 App Execution Alias 生效：

```powershell
vcore-uwp-demo.exe environment
vcore-uwp-demo.exe status

$config = (Resolve-Path example/windows-uwp/demo.yaml).Path
vcore-uwp-demo.exe start $config
vcore-uwp-demo.exe status
vcore-uwp-demo.exe stop
```

典型响应：

```json
{"success":true,"data":{"status":"disconnected","snapshotToken":null},"error":""}
```

`start` 成功时返回 `connected` 和内容寻址的 `snapshotToken`。不要解析错误文本判断状态；使用 `success` 和 `data.status`。

`demo.yaml` 只用于 lifecycle smoke：

- 它不包含真实凭据；
- 它假设外部 SOCKS5 服务监听 `127.0.0.1:1080` 并支持 UDP；
- 未启动 SOCKS5 时 VPN 仍可进入 Connected，但业务流量会按流失败；
- `dns.enable: false` 表示 TCP/UDP 53 保留原目标并作为普通流量走 SOCKS5；
- 外部 SOCKS5 服务自行负责其外层 socket 的 VPN 绕过和进程生命周期。

要验证真实流量，请把命令中的 YAML 换成自己的合法 VCore TUN 配置，或先启动符合上述约束的外部 SOCKS5 服务。不要把真实配置、secret 或响应前的完整请求写入日志。

## 前台调用契约

`demo.cpp` 直接链接构建产物的 `vcore.dll.lib`，运行时从同目录加载 `vcore.dll`：

```cpp
#include "vcore.h"

char* response = VCoreWindowsVpnInvoke(request_json);
if (response != nullptr) {
    // 读取 UTF-8 JSON；不要使用 host allocator 释放。
    VCoreFree(response);
}
```

约束：

- 请求是 NUL 结尾 UTF-8 JSON，最大 1 MiB；
- revision 固定为 `bridgeVersion: 1`；
- DTO 严格拒绝未知字段；
- 返回内存必须由同一份 `vcore.dll` 的 `VCoreFree` 释放；
- 桥接命令不能重叠；真实前台应在单进程内串行调用，本命令行 demo 额外用 session-local named mutex 串行化多个 alias 进程；
- 调用进程必须具有当前 MSIX package identity；unpackaged EXE 会失败关闭；
- 不要从 Provider 回调、Session Host 或 AppContainer UI 重入该接口。

最小宿主只使用四个方法：

| 方法 | payload | 用途 |
| --- | --- | --- |
| `getEnvironment` | `{}` | 验证 package identity，返回 PFN 和 LocalState 路径 |
| `getVpnStatus` | `{}` | 查询同包唯一 profile |
| `startVpn` | `configYaml` + `networkSettings` | 发布快照并连接 |
| `stopVpn` | `{}` | 断开当前 profile |

桥接还提供 `getStartupTaskStatus` 和 `setStartupTaskEnabled`。本 demo 故意不声明 StartupTask，避免登录时启动一个无 UI 的命令行工具；产品需要该能力时，再声明 `xmlns:desktop="http://schemas.microsoft.com/appx/manifest/desktop/windows10"`、把 `desktop` 加入 `IgnorableNamespaces`，并在前台 `<Application>` 下增加：

```xml
<desktop:Extension Category="windows.startupTask"
                   Executable="YourHost.exe"
                   EntryPoint="Windows.FullTrustApplication">
  <desktop:StartupTask TaskId="OneVCoreStartup"
                       Enabled="false"
                       DisplayName="Your App" />
</desktop:Extension>
```

## `startVpn` 请求

最小请求形状：

```json
{
  "bridgeVersion": 1,
  "method": "startVpn",
  "payload": {
    "configYaml": "tun:\n  enable: true\n...",
    "networkSettings": {
      "ipv4Address": "192.168.3.1",
      "ipv6Address": "fd00::2",
      "dnsIpv4Address": "223.5.5.5",
      "dnsIpv6Address": "2400:3200::1"
    }
  }
}
```

`networkSettings` 是 session settings，不属于用户 RAW YAML：

- 四项都必填并且必须是对应地址族的合法单播地址；
- TUN 地址不能与同地址族 DNS 地址相同；
- 不能使用 unspecified、loopback、link-local、multicast，IPv4 也不能使用 broadcast；
- 配置内容或任一地址变化时，活动会话不会 hot-swap，必须先 `stopVpn`；
- 完全相同的配置和地址重复 `startVpn` 是幂等查询，不创建第二个 Session Host。

VCore 会校验 YAML、发布内容寻址快照，并只把快照令牌和四个地址写入最大 1 KiB 的 profile custom configuration。调用方不要自行创建另一个 `VpnPlugInProfile` 或维护第二份快照。

## Manifest 契约

`AppxManifest.xml.in` 中以下值是当前 VCore 代码契约：

| Manifest 项 | 必须值/规则 |
| --- | --- |
| Session Host Application Id | `SessionHost` |
| Session Host executable | `vcore-windows-session-host.exe` |
| Provider executable | `vcore-windows-vpn-host.exe` |
| Provider Application EntryPoint | `OneVCore.VpnHost.App` |
| Provider background EntryPoint | `OneVCore.VpnBackgroundTask` |
| in-process server path | `vcore.dll` |
| activatable class | `OneVCore.VpnBackgroundTask`，`ThreadingModel="both"` |
| capabilities | `internetClientServer`、`privateNetworkClientServer`、`runFullTrust`、`networkingVpnProvider` |
| minimum desktop OS | `10.0.19042.0` |

可以修改 identity、publisher、版本、前台 Application Id/EXE、显示名称、图标和 app execution alias。除非同步修改 VCore 源码，否则不要修改 `SessionHost` 和 `OneVCore.VpnBackgroundTask`。桥接还固定使用 profile 名 `OneVCore`，可选 StartupTask 固定使用 `OneVCoreStartup`；两者都按 package family 隔离。

三项 VCore 文件必须位于 package 根目录：

```text
vcore.dll
vcore-windows-vpn-host.exe
vcore-windows-session-host.exe
```

不要加入 Wintun、`LoopbackAccessRules` 或 `CheckNetIsolation` exemption。Provider 的 loopback 唤醒、同包命名管道、`/1 + /1` 路由、DNS assignment 和物理 socket 绑定都由 VCore 管理。

## 已有纯 UWP UI 的接入方式

纯 UWP UI 保持 AppContainer；在同一个 MSIX 中增加独立完全信任 broker：

```text
UWP UI
  -> AppService 或受认证的同包 IPC
  -> full-trust broker
  -> VCoreWindowsVpnInvoke
```

broker 负责 JSON bridge、命令串行化和结果回传。UWP UI 不接触 YAML 快照路径、VPN profile、Provider 管道或 Session Host PID。broker 也不能复用 `vcore-windows-session-host.exe`；Session Host 是 VCore 私有的每会话数据面进程。

本示例用 `VCoreUwpDemo.exe` 直接充当完全信任 broker/前台，因此没有加入产品特定的 AppService 协议、UI 和状态持久化。只有确实存在纯 UWP UI 时才增加这层 IPC。

## 生命周期与失败关闭

推荐宿主流程：

1. 启动时调用 `getEnvironment`，确认运行在预期 package family；
2. 调用 `getVpnStatus` 恢复系统真实状态；
3. 用户连接时构造当前 YAML 和四个地址，调用 `startVpn`；
4. UI 可以退出，VPN 与 Session Host 继续；
5. UI 重启后再次以 `getVpnStatus` 为权威；
6. 用户断开时调用 `stopVpn` 并等待结果；
7. 只有 Disconnected 时才安装或更新包。

不要在普通代理流失败时自动停止整个 VPN。Provider/Session Host 退出、控制或数据管道 EOF、非法协议、启动超时和物理网络变化由 VCore 自己失败关闭。

## 发布前检查

- 为 ARM64 和 x64 分别构建、签名并验证同架构四产物；
- 从无旁路开发文件的干净检出执行 locked build；
- 在 Windows 10 20H2 与支持的 Windows 11 上执行真实 TUN 测试；
- 验证物理 IPv4/IPv6、DNS enabled/disabled、TCP、UDP、ICMP 和 Stop 清理；
- 执行 WACK，使用 Partner Center 正式 identity/publisher；
- 获得受限能力审批后再提交 Store；
- 发布记录保存 revision、lockfile、产物 hash 和签名结果，不把这些一次性值写回本示例。

详细内部契约见：

- [`../../docs/windows-vpn.md`](../../docs/windows-vpn.md)
- [`../../docs/windows-session-runtime.md`](../../docs/windows-session-runtime.md)
- [`../../docs/invoke-api.md`](../../docs/invoke-api.md)
- [`../../docs/acceptance.md`](../../docs/acceptance.md)

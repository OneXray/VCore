# VCore Invoke API

业务接口版本为 5，配置结构修订版为 13。配置只通过内联的 `configYaml` 或 `configYamls` 传入；每份已加载的 VCore 运行时最多拥有一个公共实例。代理组实时选择沿用 Controller，不增加 Invoke method 或版本协商。

## C ABI

```c
char *VCoreInvoke(const char *request_json);
#ifdef _WIN32
char *VCoreWindowsVpnInvoke(const char *request_json);
#endif
void VCoreFree(char *response);
```

- 请求必须是以 NUL 结尾的 UTF-8 JSON。
- 非空响应由 VCore 分配，调用方必须使用同一库中的 `VCoreFree` 释放。
- 非法输入、未知方法、状态错误和 panic 返回合法失败 JSON；只有灾难性分配失败可以返回 `NULL`。
- 请求正文、响应正文、完整配置、UUID、密钥、short ID 和凭据不得写入日志。
- `VCoreWindowsVpnInvoke` 是 Windows 安装包桥接接口，不属于业务 API v5。
- `VCoreWindowsVpnInvoke` 当前在调用线程上初始化 MTA；调用线程必须尚未初始化 COM，或已经是 MTA。STA/ASTA 调用不受支持。

## 请求与响应

请求：

```json
{
  "apiVersion": 5,
  "method": "getState",
  "instanceId": "1",
  "payload": {}
}
```

成功响应：

```json
{"success":true,"data":{},"error":""}
```

失败响应：

```json
{"success":false,"data":null,"error":"invalid configuration"}
```

约束：

- `apiVersion` 必填且只能为 `5`。
- `method` 必须来自本文列出的白名单。
- `payload` 必须是对象；无参数时传 `{}`。
- 运行时级方法必须省略 `instanceId`；实例级方法必须携带 VCore 返回的非空 ID。
- 未知 envelope 字段和未知 payload 字段都会失败。
- 无业务数据的方法成功时返回空对象，不返回 `null`。
- Invoke envelope 最大 3 MiB，单份 YAML 最大 256 KiB。

## 初始化与生命周期

每份已加载的 VCore 运行时先调用：

```json
{
  "apiVersion": 5,
  "method": "initialize",
  "payload": {"dataDir": "/absolute/path"}
}
```

`dataDir` 必须是可写绝对路径。VCore 固定使用：

```text
<dataDir>/configs   # 宿主可选持久化目录，不是 Invoke 输入
<dataDir>/geodata   # VCore 管理的 GeoData 目录
```

同一路径重复初始化幂等，切换路径失败。

公共实例状态：

```text
stopped -> preparing -> prepared -> starting -> running
   ^                                      |
   +------------- stopping <-------------+

关键数据面提前退出 -> failed
```

- `instanceId` 是当前运行时内不可复用的代次令牌，不代表支持并行公共实例。
- 同一实例一次只执行一个生命周期命令，重叠命令立即失败。
- `validateConfig` 是可并发的纯校验方法。
- `measureDelay` 使用独立批次和私有工作器，不进入公共实例表。
- 不支持配置热重载；切换配置需要 `stop -> prepare -> start`。唯一的运行期路由变更是通过 Controller 修改静态 `select` 组的当前选择，它不修改已 prepare 的配置。
- `stop` 在 stopped 状态幂等；`destroyInstance` 是最终同步清理屏障。

## 方法

### `version`

运行时级方法：

```json
{"apiVersion":5,"method":"version","payload":{}}
```

返回：

```json
{
  "apiVersion": 5,
  "buildIdentity": "VCore;engine=rust;coreVersion=0.1.0;invokeApiVersion=5;configVersion=13",
  "configVersion": 13,
  "engine": "rust",
  "version": "0.1.0"
}
```

`configVersion` 是二进制报告的结构修订号，不是 YAML 字段。源码 revision 和产物 hash 由发布系统记录。

### `initialize`

参数和幂等语义见“初始化与生命周期”。成功时返回规范化后的 `dataDir`。

### `getGeoDataState`

运行时级只读方法，要求已经初始化：

```json
{"apiVersion":5,"method":"getGeoDataState","payload":{}}
```

返回 `geosite` 和 `geoip` 两项：

```json
{
  "geosite": {
    "required": true,
    "available": false,
    "updating": false,
    "lastSuccess": null,
    "nextCheck": null,
    "lastError": null,
    "etag": null,
    "hash": null
  },
  "geoip": {
    "required": false,
    "available": false,
    "updating": false,
    "lastSuccess": null,
    "nextCheck": null,
    "lastError": null,
    "etag": null,
    "hash": null
  }
}
```

时间使用 Unix 秒，hash 为小写 SHA-256。调用不会创建实例、联网或改变更新调度。

### `createInstance`

```json
{"apiVersion":5,"method":"createInstance","payload":{}}
```

返回：

```json
{"instanceId":"1"}
```

该方法只创建 stopped 状态记录。实例销毁前再次创建失败。

### `destroyInstance`

实例级方法：

```json
{"apiVersion":5,"method":"destroyInstance","instanceId":"1","payload":{}}
```

实例仍处于 prepared、running 或 failed 时，先执行与 `stop` 等价的清理。取得命令锁后，无论清理成功、失败或 panic，ID 都会永久失效；只有因 busy 在取得命令锁前被拒绝时，实例才保留。

### `validateConfig`

运行时级方法：

```json
{
  "apiVersion": 5,
  "method": "validateConfig",
  "payload": {"configYaml": "proxies:\n  - name: edge\n    ...\n"}
}
```

完成大小、YAML、结构、共享 route-target 命名空间、引用、具体节点 `dialer-proxy` 图、代理组 DAG 和字段组合校验。不创建实例、不解析远端域名、不联网，也不读取 GeoData。资产缺失不影响纯配置校验。

### `prepare`

实例级方法，只允许 stopped 状态：

```json
{
  "apiVersion": 5,
  "method": "prepare",
  "instanceId": "1",
  "payload": {"configYaml": "proxies:\n  - name: edge\n    ...\n"}
}
```

- 读取当时可用的本地 GeoData，不启动或等待下载。
- 只为直接访问物理网络的代理根节点执行引导 DNS；代理链上的域名交给下一跳。
- 为每个静态 `select` 组建立当前 session 的初始选择；省略 `default-selected` 时使用第一项，显式值必须是直接成员。
- 成功进入 prepared；失败释放临时资源并回到 stopped。
- 含 TUN 的配置从 preparing 起持有运行时本地的 TUN/protect 租约，直到停止或销毁。
- Android 只有在实际启用 TUN 时才要求事先注册 protect controller。

### `start`

Apple 和 Android 的 TUN 启动参数：

```json
{
  "apiVersion": 5,
  "method": "start",
  "instanceId": "1",
  "payload": {"tunFd":23,"tunFraming":"utun"}
}
```

Android 使用 `rawIp`。非 TUN 配置必须省略 `tunFd` 和 `tunFraming`。

- `tunFd` 由宿主借用，宿主必须预先设置 nonblocking。
- VCore 校验后建立带 `CLOEXEC` 的副本，只关闭副本。
- Apple 只接受 `utun`，Android 只接受 `rawIp`。
- 所有监听器和关键数据面成功后才进入 running。
- GeoData 更新只在启动后按需后台运行，不属于启动关键路径。
- Windows 系统 VPN 使用安装包桥接接口，不使用文件描述符启动参数。

### `stop`

```json
{"apiVersion":5,"method":"stop","instanceId":"1","payload":{}}
```

同步取消并等待监听器、Controller、TUN、netstack、DNS、会话、出站和更新任务，关闭 VCore 持有的文件描述符副本并释放平台回调租约。返回后不得继续产生数据包或调用 protect callback；本次 session 的代理组选择随之销毁。

### `getState`

```json
{"apiVersion":5,"method":"getState","instanceId":"1","payload":{}}
```

返回：

```json
{"state":"running","lastError":""}
```

异步数据面失败时状态为 `failed`，`lastError` 只包含有界且脱敏的摘要。

### `measureDelay`

运行时级方法：

```json
{
  "apiVersion": 5,
  "method": "measureDelay",
  "payload": {
    "configYamls": ["proxies:\n  - name: edge\n    ...\n"],
    "timeout": 5,
    "url": "https://cp.cloudflare.com/"
  }
}
```

返回顺序与输入一致：

```json
{
  "results": [
    {"success":true,"delay":123,"error":""},
    {"success":false,"error":"measureDelay probe failed"}
  ]
}
```

- `configYamls` 接受 1–5 份非空节点配置，`timeout` 为 1–30 秒。
- 同一运行时一次只允许一个测速批次，最多并发五个私有工作器。
- 节点配置顶层只允许 `proxies`，不接受 `proxy-groups`；`dialer-proxy` 也只能引用具体节点。VCore 推导唯一链头，且该链必须覆盖全部节点。
- 工作器只准备出站图并执行 TCP、可选 TLS 和 HTTP/1.1 HEAD；不创建公共实例、监听器、TUN、DNS、规则、嗅探器或 GeoData。
- URL 必须是无 userinfo 和 fragment 的绝对 HTTP/HTTPS URL；HTTPS 使用发布信任根。
- 任意合法 HTTP 状态都表示探测成功；不跟随重定向、不读取正文。
- 单项失败不取消其他项；方法返回前释放全部私有任务。

## Android protect

Android TUN 通过 Invoke 之外的运行时本地回调注册：

```text
ProtectFd(fd) -> bool
```

- 含 TUN 的实例必须在 `prepare` 前注册；非 TUN 和 `measureDelay` 不需要。
- 每个出站 TCP/UDP socket 在 connect 前同步调用 protect。
- 返回 false、抛出异常或 controller 失效都会使当前连接失败关闭。
- 回调必须快速、同步、非阻塞，且不能重入 Invoke 或注册接口。
- TUN 租约存活期间不能替换或注销 controller；`stop`/`destroyInstance` 是释放屏障。
- Android binding 使用 UTF-8 `byte[]`，不依赖 Modified UTF-8。

## Controller

配置 `external-controller` 后，运行时可提供回环 `GET /traffic`、`GET /group`、`GET /group/{name}`、`GET /proxies/{name}` 和 `PUT /proxies/{name}`。代理组 Controller 可以在非 TUN 的本地 HTTP 配置中运行；此时 `/traffic` 不存在。只要 Controller 管理代理组，`secret` 就必填并保护全部路由。

组成员列表是配置期固定的，选择只存于当前 Running Session。成功切换只影响之后新建的物理 TCP、UDP 和 DNS transport，不迁移既有连接、UDP association、DNS 状态或 TCP pool，也不触发 failover。Controller 查询不携带 `instanceId`，不进入 Invoke 命令锁；完整语义见 [Controller API](controller-api.md)。

## Windows 安装包桥接

`VCoreWindowsVpnInvoke` 使用独立的桥接修订版 2：

```json
{"bridgeVersion":2,"method":"getVpnStatus","payload":{}}
```

只接受六个方法：

- `getEnvironment`
- `getVpnStatus`
- `startVpn`
- `stopVpn`
- `getStartupTaskStatus`
- `setStartupTaskEnabled`

`startVpn` 的 payload 为：

```json
{
  "configYaml": "tun:\n  enable: true\n...",
  "networkSettings": {
    "ipv4Address": "192.168.3.1",
    "ipv6Address": "fd00::2",
    "dnsIpv4Address": "8.8.8.8",
    "dnsIpv6Address": "2001:4860:4860::8888"
  },
  "sessionBackend": {
    "processes": [
      {
        "executableRelativePath": "bin\\proxy-core.exe",
        "arguments": ["run", "--mode", "vpn"]
      }
    ]
  }
}
```

`sessionBackend` 可以省略。存在时包含 `1..=8` 个有序关键进程；每项只有 package installed location 内的规范 `.exe` 相对路径和有界 argv 数组。同一可执行文件可出现多次。第一版不接受 port、UDP、readiness、restart、environment、working directory 或 raw command line；任一进程退出都会使当前 VPN 会话失败关闭。

桥接把 YAML、进程顺序、路径和参数发布为 `vcore-session-v2:<sha256>` Session Snapshot。参数引用的文件由调用方保持存在且不可变，VCore 不读取或摘要其内容。`getVpnStatus.data.snapshotToken` 返回该完整 Session token。

桥接请求最大 1 MiB。它负责安装包身份、单一 VPN profile、不可变 Session Snapshot、Session Host 激活和系统 VPN 状态；不公开 profile CRUD、内部文件路径、backend 描述、参数、PID、管道名称或 Snapshot 维护。数据包、Controller 流量查询、代理组查询/切换和业务生命周期不经过该 JSON 桥接。

## 编码与安全边界

- 所有 JSON DTO 拒绝未知字段。
- 配置、错误和日志按 UTF-8 字节计数并受固定上限约束。
- TUN 原始数据包最大 1,500 字节；最终代理 UDP 负载最大 1,452 字节。
- 嵌套 UDP 协议可以增加有界帧头，但解封装后的最终负载仍受 1,452 字节限制。
- 节点和代理组定义名共享大小写敏感的严格 UTF-8 命名空间；`DIRECT`、`REJECT` 和 `RULES` 不能用作定义名。
- Secret、password、UUID、REALITY key、short ID、目标地址和完整配置不得进入日志。

# VCore Invoke API

状态：当前公共契约。业务 API version 为 5，内部配置 schema revision 为 11。配置只通过 inline `configYaml` / `configYamls` 交付；公共生命周期在每份已加载 runtime 内保持单实例。

## 1. C ABI

```c
char *VCoreInvoke(const char *request_json);
#ifdef _WIN32
char *VCoreWindowsVpnInvoke(const char *request_json);
#endif
void VCoreFree(char *response);
```

- request 必须是 NUL 结尾 UTF-8 JSON。
- 每个非空 response 都由 VCore 独立分配，调用方必须使用 `VCoreFree`。
- 非法输入、未知 method、状态错误和 panic 返回合法 failure JSON；除灾难性分配失败外不返回 `NULL`。
- 完整 request/response、配置、UUID、密钥、short ID 和凭据不得写入日志。
- `VCoreWindowsVpnInvoke` 是 package host bridge，不属于业务 API v5，见第 7 节。

## 2. Envelope

请求：

```json
{
  "apiVersion": 5,
  "method": "getState",
  "instanceId": "1",
  "payload": {}
}
```

响应：

```json
{"success":true,"data":{},"error":""}
```

或：

```json
{"success":false,"data":null,"error":"invalid configuration: ..."}
```

规则：

- `apiVersion` 必填且只能为 `5`。
- `method` 必须来自本文白名单。
- `payload` 必须是 object；无参数时使用 `{}`。
- registry method 必须省略 `instanceId`；instance method 必须携带 VCore 返回的非空 ID。
- 未知 envelope 或 payload 字段全部失败。
- 无业务数据的方法成功时返回 `{}`，不返回 `null`。

业务 Invoke envelope 最大 3 MiB；单份 YAML 最大 256 KiB。

## 3. Registry 与生命周期

每份已加载 VCore runtime 必须先调用：

```json
{
  "apiVersion": 5,
  "method": "initialize",
  "payload": {"dataDir": "/absolute/path"}
}
```

`dataDir` 必须是可写绝对路径。VCore 创建并固定使用：

```text
<dataDir>/configs   # 宿主可选持久化目录，不是 Invoke 输入
<dataDir>/geodata   # VCore 独占管理
```

同一路径重复 initialize 幂等；切换到其他路径失败。

每份 runtime 最多存在一个公共实例：

```text
stopped -> preparing -> prepared -> starting -> running
   ^                                      |
   +------------- stopping <-------------+

关键数据面提前退出 -> failed
```

- `instanceId` 是 runtime-local、不可复用的 generation token，不表示并行实例能力。
- 同一 ID 同时只执行一个生命周期命令；重叠命令 fail-fast。
- `validateConfig` 是可并发的 registry 纯校验。
- `measureDelay` 使用独立单批次 admission 和私有 worker，不进入公共实例表。
- 不支持实例内热重载；切换配置使用 `stop -> prepare -> start`。
- `stop` 在 stopped 时幂等；`destroyInstance` 是最终同步清理屏障。

## 4. Methods

### 4.1 `version`

Registry method：

```json
{"apiVersion":5,"method":"version","payload":{}}
```

成功数据：

```json
{
  "apiVersion": 5,
  "buildIdentity": "OneVCore/VCore;engine=rust;coreVersion=0.1.0;invokeApiVersion=5;configVersion=11",
  "configVersion": 11,
  "engine": "rust",
  "version": "0.1.0"
}
```

`configVersion` 是二进制兼容性 revision，不是 YAML 字段。源码 revision 和 artifact hash 由 release manifest 单独记录。

### 4.2 `initialize`

见第 3 节。成功返回规范化后的 `dataDir`。

### 4.3 `getGeoDataState`

Registry method，要求已 initialize：

```json
{"apiVersion":5,"method":"getGeoDataState","payload":{}}
```

按 `geosite` / `geoip` 返回：

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

该方法只读，不创建实例、不联网、不改变调度。时间为 Unix seconds，hash 为小写 SHA-256。

### 4.4 `createInstance`

Registry method：

```json
{"apiVersion":5,"method":"createInstance","payload":{}}
```

成功：

```json
{"instanceId":"1"}
```

只创建 stopped 状态记录，不读取配置或启动 runtime。实例销毁前再次创建失败。

### 4.5 `destroyInstance`

Instance method：

```json
{"apiVersion":5,"method":"destroyInstance","instanceId":"1","payload":{}}
```

若实例仍 prepared、running 或 failed，先执行与 stop 等价的清理。取得 command admission 后，无论清理成功、失败或 panic，ID 都会 tombstone 并永久失效；只有 admission 前因 busy 被拒绝时实例保留。

### 4.6 `validateConfig`

Registry method：

```json
{
  "apiVersion": 5,
  "method": "validateConfig",
  "payload": {"configYaml": "proxies:\n  - name: edge\n    ...\n"}
}
```

完成 size、YAML、schema、引用、代理图和组合校验。不创建实例、不解析远端域名、不联网、不读取或更新 GeoData。资产缺失不使配置校验失败。

### 4.7 `prepare`

Instance method，只允许 stopped：

```json
{
  "apiVersion": 5,
  "method": "prepare",
  "instanceId": "1",
  "payload": {"configYaml": "proxies:\n  - name: edge\n    ...\n"}
}
```

- 读取本地可用 GeoData，但不启动或等待下载。
- 只对直接连接物理网络的 proxy root 做 bootstrap DNS；链上 domain 交给下一跳。
- 成功进入 prepared；失败释放临时资源并回到 stopped。
- TUN 配置从 preparing 起持有 runtime-local TUN/protect lease，直到 stop/destroy。
- Android 仅在配置实际启用 TUN 时要求已注册 protect controller。

### 4.8 `start`

Unix TUN fd target：

```json
{
  "apiVersion": 5,
  "method": "start",
  "instanceId": "1",
  "payload": {"tunFd":23,"tunFraming":"utun"}
}
```

Android 使用 `rawIp`。非 TUN 配置必须省略 `tunFd` / `tunFraming`。

- `tunFd` 为 borrowed；宿主必须预先设为 nonblocking。
- VCore 验证后建立 CLOEXEC duplicate，只关闭 duplicate，不关闭宿主原 fd。
- Apple 只接受 `utun`；Android 只接受 `rawIp`。
- 全部 listener 和关键数据面成功后才进入 running。
- GeoData 更新只在 start 后、配置启用且有实际需求时后台执行，不进入启动关键路径。
- Windows 系统 VPN 不使用此 fd method，而使用第 7 节 package bridge。

### 4.9 `stop`

```json
{"apiVersion":5,"method":"stop","instanceId":"1","payload":{}}
```

同步取消并等待 listener、TUN、netstack、DNS、session、outbound 和 updater task，关闭 core-owned fd，并释放 platform callback lease。返回后不得继续产生 packet 或调用 protect callback。

### 4.10 `getState`

```json
{"apiVersion":5,"method":"getState","instanceId":"1","payload":{}}
```

成功：

```json
{"state":"running","lastError":""}
```

异步数据面失败时状态为 failed，`lastError` 只包含有界、脱敏摘要。

### 4.11 `measureDelay`

Registry method：

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

成功：

```json
{
  "results": [
    {"success":true,"delay":123,"error":""},
    {"success":false,"error":"measureDelay probe failed: TLS handshake failed"}
  ]
}
```

- `configYamls` 接受 1–5 份非空 node-only YAML；`timeout` 为 1–30 秒。
- 同一 runtime 只允许一个批次；Core 最多并发五个私有 worker。
- node-only YAML 顶层只允许 `proxies`。Core 推导唯一未被其他节点引用的链头，该链必须覆盖全部节点。
- Worker 直接准备 outbound graph，执行 TCP、可选目标 TLS 和 HTTP/1.1 HEAD；不创建公共实例、listener、TUN、DNS、rules、sniffer 或 GeoData。
- URL 必须是无 userinfo/fragment 的绝对 HTTP/HTTPS URL；HTTPS 使用 release trust roots。
- 任意合法 HTTP status 表示探测成功；不跟随 redirect，不读取 body。
- 结果与输入严格等长同序；单项失败不取消其他项。方法返回前全部 worker 和 task 已释放。

## 5. Android protect

Android TUN 通过 Invoke 之外的 runtime-local callback 注册：

```text
ProtectFd(fd) -> bool
```

- 含 TUN 配置的实例必须在 prepare 前注册；非 TUN和 measureDelay 不要求。
- 每个 outbound TCP/UDP socket 在 connect 前同步调用 protect。
- 返回 false、抛异常或 controller 失效使该连接 fail closed。
- Callback 必须快速、同步、非阻塞，且不能重入 Invoke 或注册接口。
- TUN lease 存活期间不能替换或注销 controller；stop/destroy 是释放前的屏障。
- Android binding 使用 UTF-8 `byte[]`，支持完整 Unicode，不依赖 Modified UTF-8。

## 6. Controller 与流量

TUN 流量不增加 Invoke method。配置 `external-controller` 后，当前 TUN runtime 提供 loopback `GET /traffic`；可选 secret 使用 Bearer 鉴权。查询不携带 `instanceId`，不进入 Invoke admission。完整语义见 [`controller-api.md`](controller-api.md)。

## 7. Windows package bridge

`VCoreWindowsVpnInvoke` 只接受：

```json
{"bridgeVersion":1,"method":"getVpnStatus","payload":{}}
```

固定六个 method：

- `getEnvironment`
- `getVpnStatus`
- `startVpn`
- `stopVpn`
- `getStartupTaskStatus`
- `setStartupTaskEnabled`

Bridge request 最大 1 MiB。它管理 package identity、单一 VPN profile、immutable snapshot、Session Host activation 和系统 VPN 状态；不公开 profile CRUD、文件路径、PID、pipe name 或 snapshot maintenance。Windows packet 数据、Controller 查询和业务 lifecycle 不经过该 JSON bridge。

## 8. 编码与安全边界

- 所有 JSON DTO 拒绝未知字段。
- 配置、错误和日志按 UTF-8 byte 计数并有固定上限。
- TUN raw packet 最大 1,500 bytes；最终 proxy UDP payload 最大 1,452 bytes。
- 嵌套 UDP 协议可以增加有界 wire header，但解封装后仍执行最终 payload ceiling。
- Secret、password、UUID、REALITY key、short ID、目标地址和完整配置不得进入日志。

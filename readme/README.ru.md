# VCore

<p align="center">
  <a href="../README.md">English</a> · <a href="./README.zh_CN.md">简体中文</a> · Русский
</p>

VCore — независимое клиентское прокси-ядро на Rust, не привязанное к конкретному хост-приложению. Через строгую YAML-конфигурацию и Invoke API v5 оно предоставляет граф прокси, DNS, правила маршрутизации, GeoData, HTTP listener, плоскость данных TUN и статистику трафика. Внутренняя ревизия схемы конфигурации — 11; она присутствует только в ответе `version` и `buildIdentity`, но не записывается в YAML.

## Возможности

- Исходящие подключения: VLESS + XHTTP + TLS/REALITY, SOCKS5 CONNECT/UDP ASSOCIATE, AnyTLS TCP/UoT и DIRECT.
- Цепочки прокси: `dialer-proxy` образует ориентированный ациклический граф произвольной длины. Если узел A указывает на B, физический путь имеет вид `client -> B -> A -> target`.
- Маршрутизация: последовательно применяются `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `GEOSITE`, `GEOIP`, `IP-CIDR`, `IP-CIDR6`, `DST-PORT`, `NETWORK` и завершающее правило `MATCH`.
- DNS: UDP/TCP nameserver с фиксированным IP, явный outbound, последовательные policy/failover, typed/opaque cache, singleflight и перехват UDP/TCP-порта 53 в TUN.
- TUN: raw IPv4/IPv6, TCP/UDP, локальные ответы ICMPv4/ICMPv6 Echo, HTTP/TLS/QUIC sniffer и четыре счётчика трафика на session.
- Listener: необязательный HTTP CONNECT/forward listener только на loopback с обязательной Basic-аутентификацией.
- GeoData: VCore управляет `geosite.dat` и `geoip.dat` в `dataDir/geodata`, загружает их по запросу и может обновлять через цепочку прокси.
- Измерение задержки: `measureDelay` принимает за вызов 1–5 конфигураций node-only, использует до пяти частных worker и сохраняет порядок входных данных в результатах.

## Конфигурация

[`docs/config.yaml`](../docs/config.yaml) — единственный полный пример. Основные ограничения:

- Размер YAML ограничен 256 KiB; неизвестные поля, anchors, aliases, пользовательские tags и устаревшие структуры отклоняются.
- На верхнем уровне должен быть хотя бы один proxy, а также `port` или включённый `tun`.
- Значения proxy `name` чувствительны к регистру и уникальны; все ссылки должны существовать, а граф прокси должен быть ациклическим.
- `rules` обязателен и должен завершаться ровно одним `MATCH`, указывающим на реальное имя proxy.
- `DIRECT` и `REJECT` — встроенные actions; любой другой action должен быть реальным именем proxy.
- Конфигурация передаётся inline через `configYaml` / `configYamls`; VCore не читает пути конфигурации хоста.
- Runtime-значения, включая Controller, TUN fd, порт и secret Controller, создаются хостом и не сохраняются в пользовательском RAW YAML.

## Жизненный цикл и ABI

Кроссплатформенные точки входа:

```c
char *VCoreInvoke(const char *request_json);
void VCoreFree(char *response);
```

Пакеты Windows также используют host bridge ревизии 2 для profile, Session Snapshot и необязательного session backend:

```c
char *VCoreWindowsVpnInvoke(const char *request_json);
```

Публичный runtime содержит один экземпляр:

```text
initialize
  -> createInstance
  -> prepare(configYaml)
  -> start
  -> stop
  -> destroyInstance
```

`instanceId` — generation token, который не используется повторно текущим runtime. Команды одного экземпляра завершаются fail-fast, если другая команда уже выполняется; чистые вызовы `validateConfig` могут выполняться параллельно. Полный envelope, методы, владение fd и контракт Android protect описаны в [`docs/invoke-api.md`](../docs/invoke-api.md).

Трафик TUN запрашивается через session-local loopback Controller:

```http
GET /traffic
Authorization: Bearer <secret>
```

Ответ представляет собой одноразовый snapshot `up/down/upTotal/downTotal`, а не непрерывный stream. Подробности — в [`docs/controller-api.md`](../docs/controller-api.md).

## Платформы

| Платформа | Плоскость данных | Статус |
| --- | --- | --- |
| iOS / macOS | Хост предоставляет utun fd; VCore дублирует его и использует синхронный device `rust-tun` с Tokio `AsyncFd` | Реализовано; footprint на реальном iOS-устройстве для Release остаётся release gate |
| Android | `VpnService` предоставляет raw-IP fd; каждый outbound socket сначала должен пройти protect callback | Реализовано; матрица реальных устройств остаётся release gate |
| Windows | AppContainer Provider на `Windows.Networking.Vpn` и отдельный full-trust runtime для каждой session; raw IP передаётся через named pipes внутри пакета | Пакет для Windows 11 ARM64 с тестовой подписью прошёл функциональные, lifecycle, pressure и bounded-batching проверки |
| Linux | — | Не поддерживается; запуск завершается fail closed |

Windows не использует слой эмуляции fd. Provider владеет только `VpnChannel`, buffers, routes, мониторингом физической сети, packet gateway и fail-closed Stop. Полный runtime VCore, Controller, DNS, rules и outbounds находятся в Session Host. Packet channel сохраняет framing protocol v1 и объединяет не более восьми уже готовых frames, не ожидая будущие packets.

## Ограничения ресурсов

Текущий TUN profile сохраняет локальные структурные пределы вместо фиксированного admission limit на общее число прикладных flows:

```text
raw packet / MTU                 1,500 bytes
packet queue                     256
ordinary event / UDP response    128
DNS ingress / DNS response       128 / 128
TCP buffer                       32 KiB per direction
TLS / XHTTP buffer               64 KiB
DNS typed cache                  256 entries
DNS opaque cache                 64 entries / 256 KiB
GeoData allocation capacity      8 MiB
```

TCP sessions, обычные UDP associations, half-open connections, outbound handshakes и активные DNS transports создаются по запросу. Структурную безопасность обеспечивают bounded queues, buffers на flow, ограничения wire/parser, timeouts, idle cleanup и caches. Цели iOS 35/45 MiB являются best-effort наблюдениями и не меняют результаты жизненного цикла.

## Документация

- [Оглавление документации](../docs/README.md)
- [Контракт конфигурации](../docs/config.yaml)
- [Invoke API](../docs/invoke-api.md)
- [AnyTLS outbound](../docs/anytls.md)
- [Клиентский протокол REALITY V1](../docs/reality-wire-protocol.md)
- [Зависимость rustls REALITY и требования к выпуску](../docs/rustls-reality-release.md)
- [Controller трафика TUN](../docs/controller-api.md)
- [ICMP и DNS в TUN](../docs/tun-icmp-dns.md)
- [Правила и assets GeoData](../docs/geodata.md)
- [Платформенный слой TUN](../docs/tun-platform.md)
- [Граница платформы Windows VPN](../docs/windows-vpn.md)
- [Runtime сессии Windows](../docs/windows-session-runtime.md)
- [Политика ресурсов runtime](../docs/runtime-resource-policy.md)
- [Матрица приёмки](../docs/acceptance.md)

## Пример

- [Минимальная интеграция Windows UWP VPN](../example/windows-uwp/README.md): Provider и Session Host в одном пакете, full-trust foreground host, MSIX manifest и запускаемый command-line demo.

## Проверка

```bash
cargo fmt --all -- --check
cargo test --all-features --all-targets
cargo clippy --locked --all-features --lib --bins -- -D warnings -A clippy::chunks-exact-to-as-chunks -A clippy::map-or-identity
cargo test --manifest-path crates/vcore-netstack/Cargo.toml --all-targets
cargo clippy --manifest-path crates/vcore-netstack/Cargo.toml --all-targets -- -D warnings
uv run --project scripts --locked vcore-scripts check c-header
uv run --project scripts --locked vcore-scripts check tls-dependencies
uv run --project scripts --locked python -m unittest discover -s scripts/tests
uv run --project scripts --locked ruff check scripts
uv run --project scripts --locked ruff format --check scripts
```

Артефакты платформ (полные команды и переменные окружения приведены в [`scripts/README.md`](../scripts/README.md)):

```bash
uv run --project scripts --locked vcore-scripts build apple
uv run --project scripts --locked vcore-scripts build android
uv run --project scripts --locked vcore-scripts build windows --architecture arm64
```

Выполненные проверки и отложенные release gates для физических устройств и Windows перечислены в [`docs/acceptance.md`](../docs/acceptance.md).

## Credits

VCore использует реализационные основы, архитектурные решения и результаты interoperability следующих проектов:

- [smoltcp](https://github.com/smoltcp-rs/smoltcp), [clash-rs](https://github.com/Watfaq/clash-rs) и [netstack-smoltcp](https://github.com/automesh-network/netstack-smoltcp): userspace IP stacks и TUN netstacks.
- [windows-rs](https://github.com/microsoft/windows-rs), [UWP VPN Plugin Sample](https://github.com/microsoft/UwpVpnPluginSample), [wireguard-uwp-rs](https://github.com/luqmana/wireguard-uwp-rs), [Maple](https://github.com/YtFlow/Maple) и [YtFlowCore](https://github.com/YtFlow/YtFlowCore): Windows VPN, активация WinRT и packet flow.
- [Xray-core](https://github.com/XTLS/Xray-core), [Mihomo](https://github.com/MetaCubeX/mihomo) и [Leaf](https://github.com/eycorsican/leaf): прокси-протоколы, маршрутизация, архитектура TUN и interoperability references.
- [rustls](https://github.com/rustls/rustls): реализация TLS и основа VCore REALITY fork.

## Лицензия

VCore распространяется по [лицензии MIT](../LICENSE).

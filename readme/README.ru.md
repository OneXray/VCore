# VCore

<p align="center">
  <a href="../README.md">English</a> · <a href="./README.zh_CN.md">简体中文</a> · Русский
</p>

VCore — встраиваемое прокси-ядро на Rust для VPN-клиентов и локальных прокси. Оно маршрутизирует TCP/UDP-трафик через прямые соединения, прокси-узлы, группы и цепочки, объединяя DNS, GeoData и кроссплатформенную плоскость данных TUN.

Конфигурация использует **совместимый с Mihomo YAML в пределах поддерживаемых возможностей**. VCore ориентирован на клиентские функции и не реализует все поля Mihomo или его полный Dashboard API.

## Что умеет VCore

- **Принимать трафик приложений и VPN:** пересылка HTTP, CONNECT и Upgrade; SOCKS5 CONNECT и UDP ASSOCIATE; IPv4/IPv6-пакеты TUN, предоставленные хостом.
- **Маршрутизировать по назначению:** правила по домену, суффиксу или ключевому слову домена, IP CIDR, порту назначения, TCP/UDP, GeoSite и GeoIP, с явными действиями DIRECT и REJECT.
- **Выбирать прокси и строить цепочки:** вложенные группы `select`, переключение групп во время работы и цепочки `dialer-proxy`, ссылающиеся на узлы или группы. Изменения выбора применяются к новым физическим транспортным соединениям, не перенося существующие.
- **Обрабатывать DNS:** управляемые UDP/TCP-серверы, политики выбора серверов по GeoSite, последовательное переключение при отказе, кеширование и объединение одинаковых запросов; перехват TCP/UDP-порта 53 в режиме TUN.
- **Определять трафик для маршрутизации:** извлечение домена из HTTP, TLS и QUIC, а также DNS-подсказки TUN, без изменения фактического назначения. На ICMPv4/ICMPv6 Echo ядро отвечает локально.
- **Управлять данными маршрутизации:** загрузка используемых категорий из `geosite.dat` / `geoip.dat` по запросу и обновление файлов через заданный маршрут. GeoSite поддерживает Domain, Full, Plain и Regex, пересечение атрибутов и инверсию; GeoIP поддерживает инверсию. На всех платформах выбранные записи сохраняются без жёсткого лимита количества или усечения; общая квота памяти GeoData не задана. См. [границы GeoData](../docs/geodata.md#内存与安全边界).
- **Предоставлять средства управления клиенту:** Controller на loopback-интерфейсе для выбора групп, текущей скорости и общего объёма TUN-трафика, а также изолированное измерение задержки узлов и цепочек через Invoke API.

## Прокси-протоколы

Все восемь протоколов ниже включены в сборку по умолчанию. Поддержка UDP настраивается для каждого узла.

| Протокол | Возможности |
| --- | --- |
| [VLESS](../docs/vless.md) | TCP, WebSocket / HTTPUpgrade, gRPC, HTTP-маскировка первого пакета, legacy H2, [XHTTP H1/H2/H3](../docs/xhttp.md); Vision, Encryption, REALITY, JLS, статический ECH и sing-mux в поддерживаемых сочетаниях |
| [VMess AEAD](../docs/outbounds.md#vmess-aead) | TCP, WebSocket / HTTPUpgrade, gRPC, HTTP-маскировка первого пакета и legacy H2; TCP/UDP, транспорт без TLS или со стандартным TLS |
| [Trojan](../docs/outbounds.md#trojan) | TCP/UDP через TLS TCP, WebSocket / HTTPUpgrade или gRPC |
| [Shadowsocks 2022](../docs/outbounds.md#shadowsocks-2022) | TCP/UDP; AES-128-GCM, AES-256-GCM и ChaCha20-Poly1305; цепочки идентификации AES; опциональный strict ShadowTLS v3 для TCP и UoT v2 |
| [AnyTLS](../docs/outbounds.md#anytls) | TLS-сессии и UDP over TCP v2 |
| [SOCKS5](../docs/outbounds.md#socks5) | CONNECT и UDP ASSOCIATE, с опциональной аутентификацией по имени пользователя и паролю |
| [Hysteria2](../docs/outbounds.md#hysteria2) | TCP/UDP через QUIC, управление пропускной способностью, Salamander, смена портов и mTLS |
| [TUIC v5](../docs/outbounds.md#tuic-v5) | TCP/UDP через QUIC, режимы передачи UDP native/quic и выбор алгоритма управления перегрузкой |

Стандартные TLS-соединения поддерживают проверку сертификатов и закрепление сертификата по SHA-256. Поддерживаемые TCP-пути с TLS могут использовать шаблоны ClientHello Chrome, Firefox или Safari; `client-fingerprint` не зависит от `fingerprint` сертификата. Точные имена и сочетания описаны в [профилях TLS и политике сертификатов](../docs/tls-client-fingerprint.md). Эти функции не гарантируют неотличимость от браузера или произвольные сочетания протоколов.

SS2022 использует официальную Rust-библиотеку без изменений; известные риски пустой первой записи, сценария server-first и padding описаны в [контракте Shadowsocks](../docs/outbounds.md#shadowsocks-2022).

## Конфигурация в стиле Mihomo

Используйте привычные структуры `proxies`, `proxy-groups`, `rules`, `dns`, `mixed-port` и `tun`. Например:

```yaml
mixed-port: 1080
allow-lan: false

proxies:
  - name: edge
    type: anytls
    server: proxy.example.com
    port: 443
    password: replace-with-your-password
    client-fingerprint: chrome
    udp: true

proxy-groups:
  - name: Proxy
    type: select
    proxies: [edge, DIRECT]

dns:
  enable: true
  nameserver:
    - "udp://223.5.5.5:53#DIRECT"

rules:
  - GEOSITE,cn,DIRECT
  - GEOIP,cn,DIRECT,no-resolve
  - MATCH,Proxy
```

Замените адрес сервера и учётные данные в примере. Для правил GeoSite/GeoIP нужны соответствующие файлы в `<dataDir>/geodata`; без них эти типы правил недоступны. См. [полный справочник конфигурации](../docs/config.yaml) и [поведение GeoData](../docs/geodata.md).

`mixed-port` принимает HTTP и SOCKS5 на одном TCP-порту и включает SOCKS5 UDP на том же порту. `allow-lan` управляет адресом привязки независимо от `authentication`: если `authentication` отсутствует или равен `[]`, аутентификация не требуется ни на loopback, ни на всех интерфейсах; заданные учётные данные проверяются HTTP и SOCKS5. Поля верхнего уровня `port`, `socks-port`, `udp` и `listeners` отклоняются; `port` и `udp` прокси-узла сохраняют смысл параметров исходящего соединения.

Совместимость ограничена документированными полями и поведением и не распространяется на произвольные конфигурации Mihomo. Группы пока поддерживают статический `select`; DNS-серверы задаются буквальными IP-адресами и используют UDP/TCP. Providers, автоматический выбор в группах, зашифрованный DNS и fake-IP не входят в текущий набор возможностей. Неизвестные поля и недопустимые сочетания отклоняются, а не игнорируются; особенности семантики VCore отмечены в соответствующих контрактах.

Хост передаёт YAML inline через `configYaml`; дескрипторы TUN и платформенные callbacks предоставляются отдельно через runtime API. VCore не читает пути конфигурации хоста и не настраивает системные маршруты Linux автоматически.

## Платформы и интеграция

| Платформа | Интеграция TUN |
| --- | --- |
| iOS / macOS | Дескриптор файла utun, предоставленный хостом |
| tvOS 17+ | Дескриптор файла utun, предоставленный хостом; ARM64-устройства и симулятор |
| Android | Дескриптор `VpnService` с защитой исходящих сокетов |
| Linux | Настоящий raw-IP TUN с одной очередью; создание интерфейса и изоляцию маршрутизации обеспечивает хост |
| Windows | Нативный Provider на `Windows.Networking.Vpn` и полностью доверенный Session Host, без Wintun или эмуляции fd |

VCore — библиотека, а не самостоятельное VPN-приложение. На Unix исходный дескриптор TUN принадлежит хосту; VCore использует и закрывает собственную копию. Публичный API packetFlow от Apple не гарантирует доступ к raw fd, поэтому интеграция с Network Extension и проверка на устройствах остаются ответственностью хоста. См. [интеграцию TUN](../docs/tun-platform.md) и [границы приёмки платформ](../docs/acceptance.md).

Кроссплатформенный C ABI принимает JSON-запросы через Invoke API:

```c
char *VCoreInvoke(const char *request_json);
void VCoreFree(char *response);
```

Один публичный экземпляр проходит жизненный цикл `initialize → createInstance → prepare(configYaml) → start → stop → destroyInstance`. API также предоставляет проверку конфигурации, запросы состояния, статус GeoData и измерение задержки. См. [Invoke API](../docs/invoke-api.md), [Controller API](../docs/controller-api.md) и [пример интеграции Windows](../example/windows-uwp/README.md).

## Benchmark

[**TUN-бенчмарк VCore / Mihomo**](https://github.com/YuanDevTeam/container-benchmark) содержит воспроизводимую методику, результаты измерений и сравнительные графики для обоих ядер в одинаковой среде с нативным Linux TUN.

Проект benchmark также выполняет проверку совместимости протоколов (`interop`) и тесты нагрузки на память (`stress`), используя явно указанный checkout `--source vcore=PATH`. Собственные скрипты VCore только компилируют ядро и платформенные артефакты.

Он измеряет смешанный TCP/UDP-трафик на **1 / 1,5 / 2 Гбит/с** с **1 000 DNS-запросов/с** и расширенными правилами `geosite:cn` / `geoip:cn`, показывая фактическую пропускную способность, CPU, наблюдаемый пиковый Linux RSS, потери UDP-пакетов и успешные DNS-запросы. Проверяется путь TUN/DNS/маршрутизации с выходом через DIRECT, а не пропускная способность зашифрованных прокси; Linux RSS не отражает потребление памяти Apple Network Extension.

Отдельная команда `stress` использует те же полные категории `geosite:cn` / `geoip:cn` с нагрузкой 2 Гбит/с, 60 секунд и 1 000 DNS-запросов/с. Исходные DAT загружаются без усечения, но в память выбираются только категории CN. Опция `--geodata-update` добавляет реальную загрузку и перезагрузку во время трафика. Типы входных записей, измерения и ошибки приведены в README benchmark. Отдельное наблюдение не гарантирует память ниже 50 000 000 байт для произвольного входа и не заменяет проверку на устройствах Apple.

## Документация

- [Указатель документации](../docs/README.md)
- [Справочник конфигурации](../docs/config.yaml)
- [Сборка ядра и платформенных артефактов](../scripts/README.md)
- [Регрессионные тесты ядра](../tests/README.md)
- [Политика ресурсов](../docs/runtime-resource-policy.md)
- [Приёмка и известные ограничения](../docs/acceptance.md)

## Благодарности

VCore использует публичные зависимости и опирается на реализации протоколов и примеры платформенной интеграции:

- Зависимости TUN: локальный [`vcore-netstack`](../crates/vcore-netstack/README.md) использует [smoltcp](https://github.com/smoltcp-rs/smoltcp), а пакетный I/O на Unix — [tun-rs](https://github.com/tun-rs/tun-rs).
- Архитектурные ориентиры для сети и маршрутизации: [clash-rs](https://github.com/Watfaq/clash-rs), [netstack-smoltcp](https://github.com/cavivie/netstack-smoltcp), [Mihomo](https://github.com/MetaCubeX/mihomo), [Xray-core](https://github.com/XTLS/Xray-core) и [Leaf](https://github.com/eycorsican/leaf). Эти проекты не являются зависимостями netstack.
- TLS и Shadowsocks: [rustls](https://github.com/rustls/rustls), [boring](https://github.com/cloudflare/boring), [BoringSSL](https://boringssl.googlesource.com/boringssl/) и [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust). Заимствованный код replay-window сохраняет [уведомления MIT](../src/outbound/shadowsocks/packet_window.rs).
- Интеграция Windows: [windows-rs](https://github.com/microsoft/windows-rs), [UWP VPN Plugin Sample](https://github.com/microsoft/UwpVpnPluginSample), [wireguard-uwp-rs](https://github.com/luqmana/wireguard-uwp-rs), [Maple](https://github.com/YtFlow/Maple) и [YtFlowCore](https://github.com/YtFlow/YtFlowCore).

## Лицензия

[MIT](../LICENSE).

# Selected client-fingerprint acceptance (selected-v1)

`selected-v1.json` freezes seven public names, four template identities, required
gate IDs, commands, time limits and assertions. It is a **declaration, not a test
result**. Commands run from the named repository; they never infer an adjacent
checkout. Replace `{fresh-run}` with a new directory directly under
`target/interop/runs/` and `{reference-run}` with the captured run. Future gates
marked `planned_entrypoint` remain NOT RUN until their implementation exists;
zero selected tests and partial runs cannot pass a stage. The additional coverage
requirements are binding, not optional work outside the declared gates.

## Independent wire baseline

`mihomo-selected-v1.json` retains eight small synthetic, raw TLS observations:
four templates, ordinary TCP TLS and classic REALITY. The official latest Mihomo
binary was downloaded, not compiled from the reference source. Binary identity,
uTLS build dependency, raw record layout, handshake bytes and parsed fields are
retained. `validate_capture` re-parses raw bytes and detects altered derived data.
These are public ephemeral key shares and synthetic names, not private keys,
proxy credentials, application traffic or user destinations.

The full 116-case run stays in ignored `target/interop/runs/`: six enabled names
across TCP/WS/gRPC/REALITY, two SNI lengths and two successive connections; four
`none` controls; four actual templates with TLS1.2/1.3 handshakes on a native
OpenSSL observer. All server roles and the official client run in owned isolated
containers. Success means **reference captured / baseline verified**, not VCore
support, REALITY authentication or proxy interoperability. A capture-only observer
intentionally aborts; OpenSSL handshake cases do not implement VLESS or HTTP.

## Comparison rules

The bounded parser preserves ordered cipher/signature/group/share vectors,
extension payloads, ALPN/ALPS, versions, compression, ECH outer shape, padding,
session IDs' widths, ticket lengths and PSK identity/binder widths. Crypto bytes
and time-dependent ages remain in raw evidence but are not compared for equality.
GREASE values are normalized while position, width and group/share association
remain checked. Chrome shuffles only eligible slots; fixed GREASE/padding/PSK
positions are not sorted away. Firefox/Safari use fixed extension order.

The reference checker additionally validates source-defined variants before
normalizing them: exact SNI and caller-context ALPN; Chrome's ECH payload sizes
144/176/208/240; Firefox's 239-byte payload and AES128-GCM/ChaCha20 choice; and
Chrome120/Safari's conditional padding to 512 bytes. Chrome133 has no padding.
Changes outside those allowances fail comparison. Goldens are not regenerated
from the implementation under test to silence mismatches.

Sources: [Mihomo TLS connection path](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/component/tls/utls.go),
[pinned uTLS templates](https://github.com/MetaCubeX/utls/blob/f7d52c22f3a8d2f510ad1470f75cb6c3fe26aa37/u_parrots.go),
[ECH GREASE](https://github.com/MetaCubeX/utls/blob/f7d52c22f3a8d2f510ad1470f75cb6c3fe26aa37/u_ech.go),
[padding](https://github.com/MetaCubeX/utls/blob/f7d52c22f3a8d2f510ad1470f75cb6c3fe26aa37/u_tls_extensions.go).

## Intentional VCore differences and future gates

VCore retains a TLS1.2 floor, transport-owned ALPN, h2-only ALPS advertisement,
nonempty ALPS rejection and its bounded ordinary-TLS session cache. Safari's
TLS1.0/1.1 declarations are trimmed; Mihomo's WS Chrome still advertises h2 ALPS
when ALPN is only HTTP/1.1, which VCore deliberately does not do. Warm/resumed
hellos have separate expectations; PSK is not ignored by the comparator. These
policies do not authorize dropping unrelated cipher suites, shares or extensions.

Current production supports only `chrome120`. CF1–CF3 are fork-library work; CF4
adds public values only after authentic native templates and REALITY verification.
CF5 adds all transport, security, lifecycle, build and packaging gates. Declaration
files, library tests, public proxy data, cross-builds and physical devices are
separate evidence classes. See the [CF0 record](../../docs/acceptance/client-fingerprint-selected/CF0.md)
and [current TLS contract](../../docs/tls-client-fingerprint.md).

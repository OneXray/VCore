# Next-protocol coverage catalogs

These catalogs declare the accepted development targets for Trojan, VMess,
VLESS, Hysteria2 and single-peer WireGuard. They are **not** the current
production support list and contain **no successful interoperability results**.
Current supported configuration remains documented in `docs/config.yaml`.

## N0 interface experiments

The independent workspaces under `spikes/` keep candidate dependencies out of
the production workspace and lockfile. They test feasibility, not completed
outbound protocols:

- [Security experiment](spikes/security/README.md): TLS record boundaries,
  REALITY group selection and a Rust HPKE/ECH offer. Its optional negative
  compile feature is intentionally not part of a successful build.
- [Datagram experiment and commands](../../docs/acceptance/next-protocols/N0-datagram.md):
  Quinn packet/congestion injection, WG packet/timer APIs and existing Dialer
  protection rejection.
- [N0 baseline and remaining gates](../../docs/acceptance/next-protocols/N0.md).
- [Controlled QUIC native peers](spikes/hysteria2/README.md): HY2 authentication,
  one-state hopping and Xray XHTTP/H3; separate half-close failures remain
  explicit limitations, not completed production protocol fields.
- [Supplied-stream experiment](spikes/stream/README.md): TLS, ordinary WS and
  gRPC public IO wrapping, owned cancellation, official Mihomo interoperability
  and client-close differential. No production transport or YAML additions.

## Files and schema

- `fields.json`: 145 stable field IDs, full `proxies[]` paths, protocol
  applicability, exact input/default/conditional contract, required observations,
  work packages and responsible stages. XHTTP and download paths include their
  `xhttp-opts.` prefix. Values and defaults are currently normative prose in
  `contract`, not an alternative production parser.
- `combinations.json`: explicit required mode families, contract-rejection
  families, and native-peer compatibility questions. A family is **not one
  executable case** and its array dimensions are not permission to generate
  unsupported Cartesian products.

Both use `schema_version: 1`. IDs are stable; revise a requirement with a
reviewable reason rather than deleting a failing ID. Sources are public upstream
URLs or repository-relative paths. The catalogs are self-contained: future
coverage tooling must not read an external design document or source checkout.

`fields.json` has these per-field keys:

| Key | Meaning |
| --- | --- |
| `id` | Stable field identifier; unique across all 145 rows |
| `path` | Full YAML path; identical paths may have different protocol contracts |
| `protocols` | Consumers that must independently discharge the requirement |
| `contract` | Accepted values, default/absence semantics and conditional rules |
| `required_observation` | Behavior to prove, not an observed result |
| `work_packages`, `responsible_stages` | Implementation and consumer acceptance ownership |
| `default_peer` | Default official decoder, subject to matching override rules |
| `peer_override_rules` | References to mode-specific native-peer exceptions |
| `sources` | Provenance references, not test evidence |
| `behavior_status` | Initially `NOT RUN`; no imported historical passes |

Common N9 integration and N10 platform gates apply after consumer acceptance.
One shared-field row can require cases on several protocols, networks and
address families; therefore **145 fields does not mean 145 tests**.

## Peer selection

| ID | Official decoder |
| --- | --- |
| M | Mihomo native listener, the default |
| W | Linux WireGuard with wg-tools, or official wireguard-go |
| H | Hysteria 2 for shared-state port hopping and server UDP-disabled behavior |
| XR | Xray for VLESS HTTP camouflage and XHTTP H3 |
| V2 | V2Ray for legacy H2, VMess HTTP camouflage and extended standard-WS early data |

Evaluate a field's override rule against the **actual complete mode**. For
example a shared TLS field on an H3 leg uses XR, while the same field on an
ordinary Mihomo-compatible TLS leg retains M. Download legs must reach one
real native XHTTP session table, not unrelated listeners.

Source revisions provide reproducible research provenance; they do not pin test
binaries. Resolve official latest artifacts for each run and record actual
versions and hashes. WireGuard uses its official supported installation route
and additionally records kernel/module/tools provenance. A Mihomo failure is
never erased by running another peer. Add a native exception only with a
documented capability gap and retain the original result.

## Combination classification and precedence

1. Apply `rejected-by-contract` rules first. Their `rejection_phase` distinguishes
   static prepare errors from legitimate configurations whose requested traffic
   fails at dispatch/establishment, such as local `udp: false`.
2. Expand `supported-required` families into concrete legal cases. The label
   means required target with an identified native route, **not implemented or
   already interoperable**. Every value, alias and boundary still needs its own
   assertion.
3. Keep `required-but-peer-unproven` obligations separate. Their `blocked_on`
   explains what N0 must prove before the consumer can be signed off. The field
   target remains in scope. A candidate source implementation is not a wire
   proof; do not silently replace XUDP/packetaddr with raw UDP.

All initial `behavior_status` values are `NOT RUN`. No catalog entry is a
fabricated test, placeholder PASS, server fixture or production option. The
subsequent harness will attach real case IDs, exact native configurations,
expected observations, command/version identities, results and cleanup evidence.
Catalog validation alone cannot satisfy protocol acceptance.

## Important unresolved native combinations

- V2Ray recognizes CommandMux, but its researched mux decoder reads a target on
  a New frame and keeps the existing destination on Keep frames. Exact XUDP
  multi-target/reply-address behavior must be proven independently.
- V2Ray does contain packetaddr magic-destination interception and packet/stream
  wrappers. This is a candidate capability, not a reason to mark every protocol
  and transport combination passed.
- No packetaddr magic-destination decoder was identified in the researched
  Xray source. XHTTP H3 plus packetaddr remains a required unresolved combination.
- A working H3 handshake does not demonstrate all XHTTP leaf extensions,
  sing-mux, or independent download-leg inheritance/security combinations.
- Advanced wrappers on native-only transports and cross-security/cross-version
  XHTTP legs need precise legal compositions and a deployable shared handler.
  Rejection rules still take precedence, particularly H3's standard-TLS rule.

These unresolved entries are explicit development gates, not scope reductions.
No third-party source patch, custom protocol server, weakened TLS audit, or
unprotected socket is authorized by the catalogs.

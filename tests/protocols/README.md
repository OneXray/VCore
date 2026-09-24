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
- `cases.json`: frozen executable cases for N1 foundations (21 groups), N2
  Trojan (41 groups), N3 VMess (117 groups) and N4 VLESS (145 groups), with assertion names, field
  associations, official peers, input dimensions and required evidence.
- `limits.json`: shared per-object limits and executable boundary case IDs;
  `limit_foundations` compares the registered numbers with Rust constants.

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
| XR | Xray for XHTTP H3 and advanced VLESS branches |
| V2 | V2Ray for legacy H2, VMess/VLESS HTTP camouflage and extended standard-WS early data |

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
harness attaches real case IDs, native configurations, expected observations,
command/version identities, results and cleanup evidence in a separate run directory.
Catalog validation alone cannot satisfy protocol acceptance.

## N0 native questions and consumer evidence

This research list is not a substitute for current consumer results. See the
[N3 VMess report](../../docs/acceptance/next-protocols/N3.md) for the tested input,
exact transport/codec coverage and peer limits; future VLESS combinations do not
inherit VMess acceptance.

- V2Ray recognizes CommandMux, but the N0 research found different New/Keep
  target handling. N3 verifies its missing transports with separate associations
  for each target type; same-association target changes and source isolation use
  Mihomo. Do not claim V2Ray multi-target equivalence from those results.
- N3 proves VMess packetaddr against native decoders, including controlled
  domain resolution and actual peer buffer limits. The existence of V2Ray's
  magic-destination wrapper alone still proves no other protocol combination.
- No packetaddr magic-destination decoder was identified in the researched
  Xray source. XHTTP H3 plus packetaddr remains a required unresolved combination.
- A working H3 handshake does not demonstrate all XHTTP leaf extensions,
  sing-mux, or independent download-leg inheritance/security combinations.
- Advanced wrappers on native-only transports and cross-security/cross-version
  XHTTP legs need precise legal compositions and a deployable shared handler.
  Rejection rules still take precedence, particularly H3's standard-TLS rule.

Remaining unresolved entries are explicit development gates, not scope reductions.
No third-party source patch, custom protocol server, weakened TLS audit, or
unprotected socket is authorized by the catalogs.

## Declaration validation

From the VCore repository root:

```sh
uv run --project scripts --locked vcore-scripts check protocol-coverage --catalog-only
```

This explicit mode checks the complete schema-v1 ID sets (145 fields, 69 mode
families), references, ownership, native-peer declarations and required metadata.
It also preserves the declared 64 ordered upstream pairs. A valid result is
`VALID` with behavior status `NOT RUN`, never protocol acceptance. Invalid inputs
exit nonzero; duplicate JSON keys and embedded declaration-level PASS statuses
are rejected. `--catalog-dir` selects a copy for inspection; the default is
repository-local and independent of the caller's working directory.

This declaration mode does not read source references, contact peers, evaluate
the prose contracts or expand family dimensions. Its historical executed record
is [N1 catalogs](../../docs/acceptance/next-protocols/N1-catalogs.md).

## Executable stage gates

```sh
uv run --project scripts --locked vcore-scripts check protocol-interop --stage N3 --list
uv run --project scripts --locked vcore-scripts check protocol-interop --stage N3 --preflight
uv run --project scripts --locked vcore-scripts check protocol-interop --stage N3
uv run --project scripts --locked vcore-scripts check protocol-coverage --stage N3 --run-dir target/interop/runs/<run-id>
```

N3 and N4 are container-only stage runners; all peers, origins and upstream
listeners follow the [isolation rule](../../docs/testing-isolation.md). Historical
N1/N2 catalogs and reports remain available, but their server runners are not
fully migrated and must not be rerun on the host. `--case` (repeatable) and
`--protocol` select subsets for development, not full-stage acceptance. Empty,
unknown or contradictory selections fail. N3/N4 preflight downloads fresh official
M/V2 artifacts, checks versions inside owned containers, and verifies readiness
and cleanup without declaring business acceptance.

N3 has 109 native wire/public-consumer cases and eight local gates: configuration,
codecs, cancellation, regression, Release, features, offline scripts, and quality
including Apple/Android builds. Its 30 applicable field rows require the full
structured report, not the catalog's VALID status.

Replace `--stage N3` with `--stage N4` for VLESS: 136 native wire/public
consumer cases and nine local gates (configuration, codecs, transports, Vision,
regression, Release, features, scripts, and quality/builds), covering 39 applicable
field rows. Ordinary TLS and REALITY Vision must each prove inner TLS 1.3
direct-mode bytes; inner TLS 1.2/non-TLS remain separate controls. Four transport
families each run 20 public lifecycle and 20 owned-resource cycles. Eighteen
close cases compare the real Mihomo client against the same isolated native peer.
Three WS + REALITY cases (standard WS and normal/fast-open HTTPUpgrade) have
separately labeled layered close checks: VCore still connects
to the REALITY listener, while the Mihomo reference uses a standard-TLS WS
listener because its WS client does not implement REALITY. This is not a
same-combination differential result; base/negative cases independently exercise
the real WS + REALITY listener.
Existing XHTTP three-mode and split-download regressions are included; N5 new
XHTTP branches and N7 advanced security remain separate, unclaimed gates.

N1's historical 21 required groups include configuration/limit/TLS/stream/XUDP/datagram/
QUIC/resolution/resource assertions, nine native stream cases, the existing
Mihomo extended regression, feature smokes and offline harness failure tests.
`row_ids` associate a foundation with future consumers; a group-level PASS does
not sign off all modes or values of that field. Native stream probes use synthetic
VLESS framing to reach official decoders, not newly registered production YAML.
QUIC fixtures prove controlled packet IO, not completed Hysteria2 or WireGuard.

Rust writes BEGIN/PASS/FAIL JSONL only when `VCORE_CASE_EVENTS` names the owned
run's evidence file. Drop during unwinding emits FAIL; resource cases attach
baseline/peak/Stop/quiet snapshots. Python requires exact assertion sets, successful
commands and joined peers. Reports retain hashes of raw structured events, not
console PASS counts. Coverage rejects missing/duplicate/unknown results, CFG-only,
nonidle resources, failures, blocked/not-run cases and incomplete cleanup, and
recomputes results from the original hashed artifacts.

Each execution creates a fresh `target/interop/runs/<run-id>/`; its run identity
includes source/dirty-patch/lock hashes and toolchain/SDK/build identity. Temporary
synthetic credentials are removed. No external checkout or document is a runtime
input. Detailed CLI, process ownership and evidence semantics are in
[scripts](../../scripts/README.md); durable stage results live under
`docs/acceptance/next-protocols/` and distinguish foundations, protocol consumers,
platform cross-builds and physical/remote acceptance.

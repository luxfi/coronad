# coronad — offline Corona (Ringtail / Module-LWE) threshold-signer service

`coronad` orchestrates the EXISTING corona kernel (`github.com/luxfi/corona`) to
produce the `warp.CoronaEvidence` the warp Corona finality lane verifies. It
adds **no lattice crypto** — every cryptographic operation is a corona kernel
call. It is the Corona-lane realization of warp's `CoronaDKG2Signer` boundary
(`warp/offline_signers.go`).

## Why a standalone module (not `corona/cmd/coronad`)

The dependency law: **warp imports corona; corona MUST NOT import warp** (that
closes the cycle `warp -> corona -> warp`). `coronad` emits `warp.CoronaEvidence`
and uses `warp/pulsar.SerializeCoronaSig` + `warp.CoronaSigningBytes`, so it must
sit ABOVE both. Putting it in `corona/cmd` would make the corona module import
warp — forbidden. Hence `github.com/luxfi/coronad`, importing corona + warp.

```
corona  (kernel: keyera DKG, threshold sign, reshare)   -- never imports warp
warp    (CoronaEvidence, RingtailVerifier, suites)      -- imports corona
coronad (this module)                                   -- imports both
```

## Module wiring (go.mod)

- `require github.com/luxfi/corona v0.8.0`, `github.com/luxfi/warp v1.23.0`.
- `replace` BOTH to their local working trees. corona because coronad drives the
  unreleased keyera/threshold/reshare API (v0.8.0 line; the v0.7.6 warp pins is
  older — `GenerateKeys` vs `GenerateKeysTrustedDealer`, `Round1` w/o error).
  warp because the typed-evidence API the task targets (CoronaEvidence,
  subject-agnostic `VerifyRingtailThreshold(subject, ev)`, `CoronaDKG2Signer`)
  is the working-tree shape. Forcing the WHOLE graph to local corona keeps
  `corona.Signature`/`GroupKey` a SINGLE type across coronad and warp/pulsar
  (no version-skew type mismatch). warp's library (pulsar.go) uses only stable
  corona symbols, so it compiles fine against local corona; only warp's own
  _test.go uses the renamed API, and coronad's build never compiles those.
- Build env: `SDKROOT="$(xcrun --show-sdk-path)" GOWORK=off GOFLAGS=-mod=mod GOPRIVATE=github.com/luxfi/*`.
  The `ld: warning: search path .../luxcpp/install/lib not found` is harmless
  (accel CGO dep).

## Files (orthogonal concerns, one each)

- `era.go` — `Era`: committee key-era state. `Bootstrap` (dealerless Pedersen-VSS
  DKG via `keyera.Bootstrap`), `Reshare`/`Refresh` (advance Generation, preserve
  GroupKey), accessors, `Member`.
- `member.go` — `Member`: one member's OWN share + `sessionSigner` (swaps in the
  active-set Lagrange coefficient; secret never leaves the member).
- `transport.go` — `Transport` interface (two all-gather rounds + Abort) and
  `TransportFactory`.
- `loopback.go` — `Loopback`: in-process, concurrent, barrier-synchronized
  transport (race-clean). Production wraps corona's `networking` (ZAP P2P).
- `session.go` — `SigningSession.Run`: Round1->Round2->Finalize over the
  transport; recomputes Lagrange for the ACTIVE participant set (true t-of-n).
- `signer.go` — `Signer` implements `warp.CoronaDKG2Signer`. `ThresholdSign`
  derives `warp.CoronaSigningBytes(subject)`, runs the session, self-verifies
  fail-closed, emits evidence.
- `evidence.go` — `ToEvidence`: `*threshold.Signature` -> `warp.CoronaEvidence`
  via `warp/pulsar.SerializeCoronaSig`.
- `resolver.go` — `EraResolver` implements `warp/pulsar.CoronaGroupKeyResolver`.
- `activation.go` — post-reshare circuit-breaker: `SignActivation` /
  `VerifyActivationCert` (wraps `reshare.VerifyActivation`).
- `cmd/coronad` — CLI: `version`, `demo` (in-process bootstrap->sign->verify).

## Threshold semantics

The KEY is a genuine `(t,n)` Shamir sharing of the lattice secret, generated
DEALERLESSLY. SIGNING recomputes Lagrange for whatever participant set shows up
(`>= t`), so ANY t-of-n subset can sign — proven by the e2e (strict 3-of-5
`{0,2,4}` verifies). Fewer than t cannot (kernel `minority_soundness_test`:
PRF masks telescope to zero only over the declared set).

## No-reconstruct

Each `Member` holds only its own `SkShare`. The `Transport` carries only public
`Round1Data`/`Round2Data` (structurally — neither type contains a share);
`Finalize` aggregates only public `z` partials. A secret share is NEVER
centralized during signing. (The in-process `Era` holds all shares only because
the reference DKG runs in one process; production = one share per node via the
distributed dkg2 ceremony. Signing is byte-identical either way.)

## Fail-closed

`ThresholdSign` runs `threshold.Verify` before emitting. coronad NEVER emits
evidence that won't verify on chain. Worst case under any fault = no evidence
(liveness), never invalid evidence (safety).

## Tests (all `go test -race ./...` green, ~23s)

- `TestEndToEnd_CoronadSigns_WarpVerifies` — headline: 3-of-5 bootstrap, sign a
  quasar-M subject, warp `RingtailVerifier` ACCEPTS (33052-byte sig).
- `TestTrueThreshold_StrictSubsetSigns` — strict t-subsets verify; t-1 refused.
- `TestVerifierRejectsTamperedAndWrongEra` — tampered subject / wrong gen /
  corrupt sig all rejected.
- `TestReshareAndRefreshPreserveGroupKey` — Refresh+Reshare advance Generation,
  key preserved.
- `TestOnChainRegistryPath` — verify under a WIRE-deserialized GroupKey (fresh
  ring Params) — the production registry path.
- `TestSuiteMismatchRejected`, `TestActivationCircuitBreaker`.

## Production hardening (NOT done — see RED HANDOFF in handoff notes)

- Real network transport (wrap corona/networking ZAP P2P; add round timeouts +
  authenticated channels). The loopback passes pointers in-process.
- Distributed DKG custody (one share per node) instead of the in-process Era.
- Liveness layer to choose a live t-subset and retry (coronad signs the set it
  is given; it does not detect availability).
- Distributed reshare VSR exchange (commit/complaint transcript) feeding the
  activation cert; coronad provides the sign/verify halves only.
- Share persistence + committee membership sourced from chain.

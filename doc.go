// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package coronad is the OFFLINE Corona (Ringtail / Module-LWE lattice)
// threshold-signer service. It orchestrates the EXISTING corona kernel
// (github.com/luxfi/corona) to produce the warp.CoronaEvidence that the warp
// Corona finality lane verifies — it does NOT reimplement any lattice crypto.
//
// # Where coronad sits
//
// The dependency law of this codebase is: warp imports corona; corona MUST NOT
// import warp (doing so would close the cycle warp -> corona -> warp). coronad
// is the offline signer that emits warp.CoronaEvidence, so it must sit ABOVE
// both:
//
//	corona (kernel: keyera DKG, threshold sign, reshare)      <- no warp import
//	warp   (evidence types, RingtailVerifier, CoronaSigningBytes, suites)
//	coronad (this module: orchestrate corona, emit warp evidence)  -> imports both
//
// This is exactly the boundary warp/offline_signers.go names with the
// CoronaDKG2Signer interface: "Concrete signers (pulsard, the corona DKG2
// signer, the P3Q prover) live in their own modules, run by validators/provers,
// and emit the typed evidence the verifiers consume." coronad is that module
// for the Corona lane; *Signer implements warp.CoronaDKG2Signer.
//
// # What coronad does
//
//  1. Era (era.go) — maintains a committee's Corona key-era state. Bootstrap
//     opens it with the dealerless Pedersen-VSS DKG (keyera.Bootstrap, no party
//     ever holds the master secret). Reshare / Refresh advance the era's
//     Generation while PRESERVING the group public key, so signatures made
//     under any generation verify under the same GroupKey.
//
//  2. SigningSession (session.go) — drives ONE Corona 2-round threshold-signing
//     session: Round1 (masked commitments) -> Round2 (partials) -> Finalize ->
//     ONE corona.Signature. It is no-reconstruct: no member's secret share ever
//     leaves the member; only the public Round1/Round2 messages cross the
//     transport, and Finalize aggregates only the public z partials.
//
//  3. Signer (signer.go) — the warp.CoronaDKG2Signer boundary. ThresholdSign
//     derives the signing bytes (warp.CoronaSigningBytes(subject)), runs the
//     session over the committee, self-verifies fail-closed, and emits
//     warp.CoronaEvidence{ChainID, KeyEraID, Generation, Sig} (Sig serialized
//     via warp/pulsar.SerializeCoronaSig) that
//     warp/pulsar.RingtailVerifier.VerifyRingtailThreshold accepts.
//
//  4. Transport (transport.go, loopback.go) — the committee round-transport
//     abstraction with an in-process, concurrent, barrier-synchronized loopback
//     implementation for tests and single-box deployment. A production network
//     transport wraps corona/networking (the kernel's existing ZAP P2P).
//
// # Threshold semantics (read this — it bounds what is and isn't guaranteed)
//
// The KEY is a genuine (t, n) Shamir sharing of the lattice secret s, generated
// DEALERLESSLY (keyera.Bootstrap / dkg2 Pedersen-VSS). The SIGNING session
// recomputes the Lagrange coefficients for whatever participant set actually
// shows up (>= t members), so ANY t-of-n subset can sign — this is true
// threshold signing, proven in the e2e test by a strict t-subset producing a
// signature that verifies under the group key. Fewer than t members cannot:
// the PRF masks telescope to zero only over the declared participant set, and a
// dropped partial leaves an uncancelled high-norm term the verify rejects
// (corona/threshold minority_soundness_test).
package coronad

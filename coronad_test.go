// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package coronad_test

import (
	"crypto/rand"
	"testing"

	"github.com/luxfi/coronad"
	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
	"github.com/luxfi/warp"

	corona "github.com/luxfi/corona/threshold"
	warppulsar "github.com/luxfi/warp/pulsar"
)

// committee returns n deterministic validator identity strings.
func committee(n int) []string {
	vs := make([]string, n)
	for i := range vs {
		vs[i] = string(rune('A'+i)) + "-corona-validator"
	}
	return vs
}

// fixedResolver is a warp/pulsar.CoronaGroupKeyResolver that returns one fixed
// group key + suite, regardless of routing. Used to exercise the on-chain
// registry path where the verifier holds a DESERIALIZED group key.
type fixedResolver struct {
	gk    *corona.GroupKey
	suite string
}

func (f *fixedResolver) ResolveGroupKey(_ [32]byte, _ uint64, _ uint64) (*corona.GroupKey, string, error) {
	return f.gk, f.suite, nil
}

// TestEndToEnd_CoronadSigns_WarpVerifies is the headline proof: a t-of-n coronad
// committee bootstraps a dealerless key era, threshold-signs a subject, and the
// warp Corona lane's RingtailVerifier ACCEPTS the emitted CoronaEvidence.
func TestEndToEnd_CoronadSigns_WarpVerifies(t *testing.T) {
	const (
		n         = 5
		threshold = 3
		keyEraID  = uint64(7)
	)
	chainID := ids.ID{0xC0, 0x12, 0x20, 0x06} // arbitrary source chain
	era, err := coronad.Bootstrap(chainID, keyEraID, threshold, committee(n), rand.Reader)
	require.NoError(t, err, "dealerless Bootstrap")
	t.Logf("bootstrapped Corona era: chain=%x keyEra=%d gen=%d  t=%d n=%d",
		chainID[:4], era.KeyEraID(), era.Generation(), era.Threshold(), era.Size())

	// The subject is a 32-byte finality digest. Use the canonical quasar
	// consensus subject M to show the verifier is subject-agnostic.
	subjectArr := warp.QuasarFinalitySubject(warp.QuasarFinalityParams{
		ChainID:     chainID,
		Height:      42,
		Round:       1,
		BlockID:     ids.ID{0xB1, 0x0C},
		SignerSetID: ids.ID{0x5e, 0x70},
		KeyEraID:    keyEraID,
		Generation:  era.Generation(),
	})
	subject := subjectArr[:]

	// coronad signs with the FULL committee.
	signer := coronad.NewSigner(era, coronad.Loopback)
	ev, err := signer.ThresholdSign(subject)
	require.NoError(t, err, "coronad ThresholdSign (full committee)")
	require.Equal(t, chainID, ev.ChainID)
	require.Equal(t, keyEraID, ev.KeyEraID)
	require.Equal(t, era.Generation(), ev.Generation)
	require.NotEmpty(t, ev.Sig)
	t.Logf("coronad emitted CoronaEvidence: %d-byte lattice threshold signature", len(ev.Sig))

	// The warp Corona lane verifies it.
	resolver := coronad.NewEraResolver()
	resolver.Add(era)
	v := warppulsar.NewRingtailVerifier(resolver)
	require.NoError(t, v.VerifyRingtailThreshold(subject, ev),
		"warp RingtailVerifier MUST accept coronad evidence")
	t.Log("PASS: coronad signed -> warp/pulsar.RingtailVerifier accepted CoronaEvidence")
}

// TestTrueThreshold_StrictSubsetSigns proves coronad is a real t-of-n signer: an
// EXACT t-of-n strict subset (3 of the 5 committee members) produces a signature
// that verifies under the group key, while t-1 members are refused fail-closed.
func TestTrueThreshold_StrictSubsetSigns(t *testing.T) {
	const n, threshold = 5, 3
	chainID := ids.ID{0x5, 0x5, 0x5, 0x5}
	era, err := coronad.Bootstrap(chainID, 1, threshold, committee(n), rand.Reader)
	require.NoError(t, err)

	subject := make([]byte, 32)
	_, _ = rand.Read(subject)

	resolver := coronad.NewEraResolver()
	resolver.Add(era)
	v := warppulsar.NewRingtailVerifier(resolver)

	// Strict t-subset {0, 2, 4} (omits 1 and 3) signs and verifies.
	subsetSigner := coronad.NewSigner(era, coronad.Loopback, 0, 2, 4)
	ev, err := subsetSigner.ThresholdSign(subject)
	require.NoError(t, err, "strict t-of-n subset must sign")
	require.NoError(t, v.VerifyRingtailThreshold(subject, ev),
		"strict t-of-n subset signature must verify under the group key")
	t.Log("PASS: strict 3-of-5 subset {0,2,4} produced a verifying signature (true t-of-n)")

	// A different strict t-subset {1, 3, 4} also signs and verifies — the share
	// at each evaluation point interpolates s for ANY t-subset.
	subsetSigner2 := coronad.NewSigner(era, coronad.Loopback, 1, 3, 4)
	ev2, err := subsetSigner2.ThresholdSign(subject)
	require.NoError(t, err)
	require.NoError(t, v.VerifyRingtailThreshold(subject, ev2))

	// t-1 members are refused fail-closed: coronad never starts a sub-quorum.
	tooFew := coronad.NewSigner(era, coronad.Loopback, 0, 1)
	_, err = tooFew.ThresholdSign(subject)
	require.ErrorIs(t, err, coronad.ErrInsufficientParticipants,
		"a sub-threshold set must be refused")
	t.Log("PASS: t-1 participants refused with ErrInsufficientParticipants")
}

// TestVerifierRejectsTamperedAndWrongEra exercises the negative paths the warp
// lane must reject.
func TestVerifierRejectsTamperedAndWrongEra(t *testing.T) {
	const n, threshold = 3, 2
	chainID := ids.ID{0xAB, 0xCD}
	era, err := coronad.Bootstrap(chainID, 4, threshold, committee(n), rand.Reader)
	require.NoError(t, err)

	subject := make([]byte, 32)
	_, _ = rand.Read(subject)
	other := make([]byte, 32)
	_, _ = rand.Read(other)

	signer := coronad.NewSigner(era, coronad.Loopback)
	ev, err := signer.ThresholdSign(subject)
	require.NoError(t, err)

	resolver := coronad.NewEraResolver()
	resolver.Add(era)
	v := warppulsar.NewRingtailVerifier(resolver)

	// Sanity: the right subject verifies.
	require.NoError(t, v.VerifyRingtailThreshold(subject, ev))

	// Tampered subject: the corona signature is over CoronaSigningBytes(subject),
	// so verifying over a DIFFERENT subject fails the lattice check.
	require.ErrorIs(t, v.VerifyRingtailThreshold(other, ev), warppulsar.ErrCoronaVerifyFailed,
		"a signature must not verify against a different subject")

	// Wrong generation: the resolver has no key for it -> resolver failure.
	evWrongGen := ev
	evWrongGen.Generation = ev.Generation + 99
	require.ErrorIs(t, v.VerifyRingtailThreshold(subject, evWrongGen), warppulsar.ErrCoronaGroupKeyResolverFailed)

	// Truncated signature bytes -> deserialize failure (still fail-closed).
	evBadSig := ev
	evBadSig.Sig = ev.Sig[:len(ev.Sig)/2]
	require.Error(t, v.VerifyRingtailThreshold(subject, evBadSig))
	t.Log("PASS: tampered subject, wrong generation, and corrupt signature all rejected")
}

// TestReshareAndRefreshPreserveGroupKey proves the key-era lifecycle: after a
// Refresh and a Reshare the Generation advances but signatures still verify
// under the SAME group key.
func TestReshareAndRefreshPreserveGroupKey(t *testing.T) {
	const n, threshold = 5, 3
	chainID := ids.ID{0x9, 0x9, 0x9}
	era, err := coronad.Bootstrap(chainID, 2, threshold, committee(n), rand.Reader)
	require.NoError(t, err)
	gen0 := era.Generation()

	subject := make([]byte, 32)
	_, _ = rand.Read(subject)

	resolver := coronad.NewEraResolver()
	resolver.Add(era)
	v := warppulsar.NewRingtailVerifier(resolver)

	// Refresh (same committee) -> generation advances, group key unchanged.
	require.NoError(t, era.Refresh(rand.Reader))
	require.Equal(t, gen0+1, era.Generation(), "Refresh must advance Generation")
	resolver.Add(era) // register the new generation
	ev, err := coronad.NewSigner(era, coronad.Loopback).ThresholdSign(subject)
	require.NoError(t, err)
	require.Equal(t, era.Generation(), ev.Generation)
	require.NoError(t, v.VerifyRingtailThreshold(subject, ev),
		"post-Refresh signature must verify under the unchanged group key")

	// Reshare onto a partially-new committee -> generation advances again.
	newCommittee := []string{"A-corona-validator", "B-corona-validator", "X-new", "Y-new", "Z-new"}
	require.NoError(t, era.Reshare(newCommittee, threshold, rand.Reader))
	require.Equal(t, gen0+2, era.Generation(), "Reshare must advance Generation")
	resolver.Add(era)
	ev2, err := coronad.NewSigner(era, coronad.Loopback).ThresholdSign(subject)
	require.NoError(t, err)
	require.NoError(t, v.VerifyRingtailThreshold(subject, ev2),
		"post-Reshare signature must verify under the unchanged group key")
	t.Logf("PASS: Refresh+Reshare advanced gen %d->%d, key preserved", gen0, era.Generation())
}

// TestOnChainRegistryPath proves the production verify path: a destination chain
// holds the group key as WIRE BYTES, deserializes it (fresh ring Params), and
// verifies coronad's evidence with that deserialized key.
func TestOnChainRegistryPath(t *testing.T) {
	const n, threshold = 3, 2
	chainID := ids.ID{0x1, 0x2, 0x3}
	era, err := coronad.Bootstrap(chainID, 5, threshold, committee(n), rand.Reader)
	require.NoError(t, err)

	subject := make([]byte, 32)
	_, _ = rand.Read(subject)
	ev, err := coronad.NewSigner(era, coronad.Loopback).ThresholdSign(subject)
	require.NoError(t, err)

	// Round-trip the group key through its canonical wire form, as an on-chain
	// registry would store and a destination chain would load it.
	gkBytes, err := era.GroupKey().MarshalBinary()
	require.NoError(t, err)
	var gk2 corona.GroupKey
	require.NoError(t, gk2.UnmarshalBinary(gkBytes))

	v := warppulsar.NewRingtailVerifier(&fixedResolver{gk: &gk2, suite: string(warp.DefaultCoronaSuiteID)})
	require.NoError(t, v.VerifyRingtailThreshold(subject, ev),
		"evidence must verify under a group key loaded from wire (fresh Params)")
	t.Log("PASS: evidence verified under a wire-deserialized group key (on-chain registry path)")
}

// TestSuiteMismatchRejected proves the Corona lane suite gate: a resolver that
// reports a non-Corona suite is rejected before any lattice work.
func TestSuiteMismatchRejected(t *testing.T) {
	const n, threshold = 3, 2
	chainID := ids.ID{0x7}
	era, err := coronad.Bootstrap(chainID, 1, threshold, committee(n), rand.Reader)
	require.NoError(t, err)
	subject := make([]byte, 32)
	_, _ = rand.Read(subject)
	ev, err := coronad.NewSigner(era, coronad.Loopback).ThresholdSign(subject)
	require.NoError(t, err)

	v := warppulsar.NewRingtailVerifier(&fixedResolver{gk: era.GroupKey(), suite: "Pulsar-SHA3-experimental"})
	require.ErrorIs(t, v.VerifyRingtailThreshold(subject, ev), warppulsar.ErrCoronaSuiteMismatch)
}

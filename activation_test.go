// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package coronad_test

import (
	"crypto/rand"
	"testing"

	"github.com/luxfi/coronad"
	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"

	"github.com/luxfi/corona/hash"
	"github.com/luxfi/corona/reshare"
)

// TestActivationCircuitBreaker proves coronad can produce the post-reshare
// activation certificate the chain's VerifyActivation gate accepts: the
// committee threshold-signs the activation message under the group key, and the
// gate verifies both the transcript-hash binding and the signature.
func TestActivationCircuitBreaker(t *testing.T) {
	const n, threshold = 3, 2
	chainID := ids.ID{0xAC, 0x71, 0x7a}
	era, err := coronad.Bootstrap(chainID, 3, threshold, committee(n), rand.Reader)
	require.NoError(t, err)

	// A reshare-transcript view (in production these come from the distributed
	// commit/complaint exchange; here we build a consistent local view).
	ti := reshare.TranscriptInputs{
		ChainID:      chainID[:],
		KeyEraID:     era.KeyEraID(),
		NewEpochID:   1,
		ThresholdOld: threshold,
		ThresholdNew: threshold,
		Variant:      "reshare",
	}
	rt := reshare.ReshareTranscript{
		QualifiedQuorum: []int{1, 2, 3},
	}
	msg := reshare.ActivationMessage{Transcript: ti, ReshareTranscript: rt}

	cert, err := coronad.SignActivation(era, coronad.Loopback, msg)
	require.NoError(t, err, "committee must produce an activation cert under the group key")
	require.NotEmpty(t, cert.Signature)

	suite := hash.Default()
	localTH := ti.Hash(suite)
	localEH := rt.Hash(suite)

	require.NoError(t, coronad.VerifyActivationCert(era, cert, localTH, localEH),
		"VerifyActivation must accept the committee's activation cert")
	t.Log("PASS: coronad produced an activation cert; reshare.VerifyActivation accepted it")

	// Negative: a chain whose local transcript differs rejects the cert.
	var wrong [32]byte
	wrong[0] = 0xFF
	require.Error(t, coronad.VerifyActivationCert(era, cert, wrong, localEH),
		"a mismatched local transcript hash must be rejected")
}

// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package coronad

import (
	"errors"
	"fmt"

	"github.com/luxfi/corona/threshold"
	"github.com/luxfi/warp"

	warppulsar "github.com/luxfi/warp/pulsar"
)

// ToEvidence serializes a Corona threshold signature into the warp.CoronaEvidence
// the Corona finality lane verifies. The signature bytes use warp/pulsar's
// canonical Corona wire form (SerializeCoronaSig) — the exact inverse of the
// DeserializeCoronaSig the RingtailVerifier runs — so emit and verify cannot
// drift. Routing (ChainID, KeyEraID, Generation) comes from the era.
func ToEvidence(era *Era, sig *threshold.Signature) (warp.CoronaEvidence, error) {
	if era == nil || era.inner == nil {
		return warp.CoronaEvidence{}, ErrUninitializedEra
	}
	if sig == nil {
		return warp.CoronaEvidence{}, errors.New("coronad: nil signature")
	}
	sigBytes, err := warppulsar.SerializeCoronaSig(sig)
	if err != nil {
		return warp.CoronaEvidence{}, fmt.Errorf("coronad: serialize corona signature: %w", err)
	}
	return warp.CoronaEvidence{
		ChainID:    era.ChainID(),
		KeyEraID:   era.KeyEraID(),
		Generation: era.Generation(),
		Sig:        sigBytes,
	}, nil
}

// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package coronad

import (
	"fmt"

	"github.com/luxfi/corona/hash"
	"github.com/luxfi/corona/reshare"
	"github.com/luxfi/corona/threshold"
)

// activationSuite is the hash suite coronad signs/verifies activation certs
// under. It MUST match the suite keyera.Bootstrap opened the era with
// (Corona-SHA3, hash.Default()) so the transcript hashes agree.
func activationSuite() hash.HashSuite { return hash.Default() }

// SignActivation drives a threshold-signing session over an activation
// message's signable bytes and returns the reshare.ActivationCert the chain's
// VerifyActivation accepts. This is the post-reshare circuit-breaker: it proves
// the (possibly new) committee can collectively sign under the UNCHANGED group
// key, so the chain may commit the new share distribution.
//
// The activation signature uses the corona kernel wire form (Signature.
// MarshalBinary), NOT the warp Corona-lane wire form — an activation cert is a
// corona-internal artifact the chain verifies with corona.Verify, never a warp
// envelope payload.
func SignActivation(era *Era, newTransport TransportFactory, msg reshare.ActivationMessage, participants ...int) (*reshare.ActivationCert, error) {
	if era == nil || era.GroupKey() == nil {
		return nil, ErrUninitializedEra
	}
	ps := participants
	if len(ps) == 0 {
		ps = fullCommittee(era)
	}

	signable := msg.SignableBytes(activationSuite())
	prfKey := deriveSessionPRFKey(era, sha256Sum(signable))
	sessionID := deriveSessionID(sha256Sum(signable))

	sess, err := NewSigningSession(era, ps, sessionID, string(signable), prfKey)
	if err != nil {
		return nil, err
	}
	sig, err := sess.Run(newTransport(sess.participants))
	if err != nil {
		return nil, fmt.Errorf("coronad: activation signing session: %w", err)
	}
	if !threshold.Verify(era.GroupKey(), string(signable), sig) {
		return nil, ErrSelfVerifyFailed
	}
	sigBytes, err := sig.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("coronad: marshal activation signature: %w", err)
	}
	return &reshare.ActivationCert{Message: msg, Signature: sigBytes}, nil
}

// VerifyActivationCert runs the chain-level activation check against era's group
// key: the cert's transcript hashes must equal the chain's local view, and the
// threshold signature must verify under the unchanged group key. It wraps
// reshare.VerifyActivation with coronad's corona-wire verify closure.
func VerifyActivationCert(era *Era, cert *reshare.ActivationCert, localTranscriptHash, localExchangeHash [32]byte) error {
	if era == nil || era.GroupKey() == nil {
		return ErrUninitializedEra
	}
	gk := era.GroupKey()
	return reshare.VerifyActivation(
		cert,
		localTranscriptHash,
		localExchangeHash,
		activationSuite(),
		func(message, signature []byte) bool {
			var sig threshold.Signature
			if err := sig.UnmarshalBinary(signature); err != nil {
				return false
			}
			return threshold.Verify(gk, string(message), &sig)
		},
	)
}

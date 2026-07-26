// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package coronad

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/luxfi/corona/threshold"
	"github.com/luxfi/ids"
	"github.com/luxfi/warp"
)

// Signer is the offline Corona threshold signer — coronad's implementation of
// warp.CoronaDKG2Signer. It composes an Era (key-era state), a participant set,
// and a TransportFactory, and emits the warp.CoronaEvidence the warp Corona
// lane verifies.
//
// Compile-time assertion that *Signer satisfies the warp boundary interface:
var _ warp.CoronaDKG2Signer = (*Signer)(nil)

type Signer struct {
	era          *Era
	participants []int
	newTransport TransportFactory
}

// NewSigner builds a Signer over era using newTransport for each session. If no
// participants are given, the full committee signs; otherwise the given subset
// (>= t members) signs.
func NewSigner(era *Era, newTransport TransportFactory, participants ...int) *Signer {
	ps := participants
	if len(ps) == 0 {
		ps = fullCommittee(era)
	}
	return &Signer{era: era, participants: ps, newTransport: newTransport}
}

// ThresholdSign implements warp.CoronaDKG2Signer. It drives a threshold-signing
// session over subject (a 32-byte finality digest — warp D or quasar M),
// self-verifies fail-closed, and returns the warp.CoronaEvidence the Corona
// lane's RingtailVerifier accepts over warp.CoronaSigningBytes(subject).
func (s *Signer) ThresholdSign(subject []byte) (warp.CoronaEvidence, error) {
	if len(subject) != 32 {
		return warp.CoronaEvidence{}, fmt.Errorf("%w: got %d bytes", ErrBadSubject, len(subject))
	}
	sid, err := ids.ToID(subject)
	if err != nil {
		return warp.CoronaEvidence{}, fmt.Errorf("%w: %v", ErrBadSubject, err)
	}

	// The corona signature is over the warp canonical signing bytes for the
	// subject. This is THE binding the on-chain RingtailVerifier checks.
	message := string(warp.CoronaSigningBytes(sid))
	prfKey := deriveSessionPRFKey(s.era, subject)
	sessionID := deriveSessionID(subject)

	sess, err := NewSigningSession(s.era, s.participants, sessionID, message, prfKey)
	if err != nil {
		return warp.CoronaEvidence{}, err
	}
	sig, err := sess.Run(s.newTransport(sess.participants))
	if err != nil {
		return warp.CoronaEvidence{}, fmt.Errorf("coronad: signing session: %w", err)
	}

	// Fail-closed: NEVER emit evidence whose signature will not verify on chain.
	// This is the same check warp/pulsar.RingtailVerifier performs (corona.Verify
	// over CoronaSigningBytes), run here before the bytes ever leave the signer.
	if !threshold.Verify(s.era.GroupKey(), message, sig) {
		return warp.CoronaEvidence{}, ErrSelfVerifyFailed
	}
	return ToEvidence(s.era, sig)
}

// sessionPRFDomain domain-separates coronad's deterministic session PRF key.
const sessionPRFDomain = "coronad.session.prfkey.v1"

// deriveSessionPRFKey derives the per-session PRF key all members must agree on.
// It is NOT secret — in the corona protocol the per-pair secrecy comes from the
// pairwise Seeds; the PRF key is a shared session/domain binder (the kernel's
// own reference path uses a constant string here). Deriving it deterministically
// from (keyEraID, generation, subject) means every member computes the same key
// with no extra coordination round.
func deriveSessionPRFKey(era *Era, subject []byte) []byte {
	h := sha256.New()
	h.Write([]byte(sessionPRFDomain))
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], era.KeyEraID())
	h.Write(u[:])
	binary.BigEndian.PutUint64(u[:], era.Generation())
	h.Write(u[:])
	h.Write(subject)
	return h.Sum(nil) // 32 bytes
}

// sha256Sum returns the 32-byte SHA-256 of b — used to fold a variable-length
// activation message into a fixed 32-byte "subject" for the session derivations.
func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// deriveSessionID folds the subject into a non-zero session id all members
// agree on. The corona kernel hedges each signature with fresh randomness, so
// reusing an id across signings of the same subject only re-derives a fresh
// nonce; it never reuses one (corona TestE2EKATReplayDeterminism). The id must
// be non-zero and consistent across members — both hold here.
func deriveSessionID(subject []byte) int {
	v := binary.BigEndian.Uint64(subject[:8])
	v >>= 1 // clear the top bit so the int is positive on 64-bit platforms
	if v == 0 {
		v = 1
	}
	return int(v)
}

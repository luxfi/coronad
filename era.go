// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package coronad

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/luxfi/corona/keyera"
	"github.com/luxfi/corona/threshold"
	"github.com/luxfi/ids"
)

// Era is a committee's Corona key-era state: the public group key, the
// per-member shares, and the (ChainID, KeyEraID, Generation) routing the warp
// Corona lane resolves against.
//
// It wraps keyera.KeyEra (the corona kernel's lifecycle type). The group key
// (A, bTilde) is fixed at Bootstrap and persists across every Reshare / Refresh
// within the era; only the share distribution and the Generation rotate.
//
// NO-RECONSTRUCT NOTE. In this in-process orchestration the Era holds ALL
// members' shares, because the dealerless DKG reference path (keyera.Bootstrap)
// runs every party's session in one process. That is the dealing/key-management
// concern. The SIGNING concern is what must be no-reconstruct, and it is: the
// SigningSession hands each Member only its OWN share and never moves a secret
// share between members or to the combiner (see session.go / member.go). In a
// distributed deployment each coronad node holds exactly one share produced by
// the distributed dkg2 ceremony; the signing protocol is byte-identical.
type Era struct {
	chainID ids.ID
	inner   *keyera.KeyEra

	// bootstrapTranscript is the public, byte-stable record of the DKG
	// ceremony. The consensus layer commits to its TranscriptHash to ratify
	// the era. Retained for the chain-commit path; nil after a Reshare (the
	// reshare exchange has its own transcript).
	bootstrapTranscript *keyera.BootstrapTranscript
}

// Bootstrap opens a new Corona key era for chainID via the dealerless
// Pedersen-VSS DKG (keyera.Bootstrap). No single party ever holds the master
// secret s. validators is the ordered committee (the order fixes each member's
// 0-indexed position); t is the reconstruction/signing threshold and MUST
// satisfy 1 <= t < n (the dkg2 honest-abort shape).
//
// entropy is the ceremony randomness; nil resolves to crypto/rand.Reader.
func Bootstrap(chainID ids.ID, keyEraID uint64, t int, validators []string, entropy io.Reader) (*Era, error) {
	if entropy == nil {
		entropy = rand.Reader
	}
	inner, transcript, err := keyera.Bootstrap(
		t,
		validators,
		0, // single Corona group (CoronaGroupID 0)
		keyera.CoronaKeyEraID(keyEraID),
		entropy,
	)
	if err != nil {
		return nil, fmt.Errorf("coronad: bootstrap: %w", err)
	}
	return &Era{chainID: chainID, inner: inner, bootstrapTranscript: transcript}, nil
}

// Reshare evolves the committee to newValidators / newThreshold while
// PRESERVING the group public key. The Generation advances by one. Signatures
// made under the new generation still verify under the same GroupKey — proven
// by the reshare e2e test. entropy nil -> crypto/rand.Reader.
//
// This drives keyera.Reshare (the in-process bare-kernel reshare). The
// chain-level activation circuit-breaker over the DISTRIBUTED reshare exchange
// (commit/complaint transcript) is a separate concern; see activation.go for
// the cert-signing/verify half coronad provides.
func (e *Era) Reshare(newValidators []string, newThreshold int, entropy io.Reader) error {
	if e == nil || e.inner == nil {
		return ErrUninitializedEra
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	if _, err := e.inner.Reshare(newValidators, newThreshold, entropy); err != nil {
		return fmt.Errorf("coronad: reshare: %w", err)
	}
	e.bootstrapTranscript = nil
	return nil
}

// Refresh rotates the share distribution among the SAME committee at the SAME
// threshold to defeat a mobile adversary, advancing the Generation while
// keeping the GroupKey. It is Reshare onto the current committee.
func (e *Era) Refresh(entropy io.Reader) error {
	if e == nil || e.inner == nil {
		return ErrUninitializedEra
	}
	return e.Reshare(e.Committee(), e.Threshold(), entropy)
}

// GroupKey returns the era's public Corona group key (A, bTilde). It is stable
// across Reshare / Refresh within the era.
func (e *Era) GroupKey() *threshold.GroupKey {
	if e == nil || e.inner == nil {
		return nil
	}
	return e.inner.GroupKey
}

// ChainID is the chain whose validators hold the threshold key.
func (e *Era) ChainID() ids.ID { return e.chainID }

// KeyEraID identifies the group-key lineage (bumps only on Reanchor).
func (e *Era) KeyEraID() uint64 { return uint64(e.inner.EraID) }

// Generation is the proactive-refresh/reshare epoch within the key era. It is
// folded into the emitted CoronaEvidence so a signature pins its share
// generation.
func (e *Era) Generation() uint64 { return e.inner.State.Generation }

// Threshold is the era's reconstruction/signing threshold t.
func (e *Era) Threshold() int { return e.inner.State.Threshold }

// Size is the committee size n.
func (e *Era) Size() int { return len(e.inner.State.Validators) }

// Committee returns a copy of the ordered validator identities.
func (e *Era) Committee() []string {
	return append([]string(nil), e.inner.State.Validators...)
}

// BootstrapTranscript returns the public DKG transcript for chain commit, or
// nil if the era has been reshared since Bootstrap.
func (e *Era) BootstrapTranscript() *keyera.BootstrapTranscript {
	return e.bootstrapTranscript
}

// Member returns the committee member at the given 0-indexed position, holding
// ONLY that member's own secret share. It is the unit the SigningSession runs
// per participant.
func (e *Era) Member(index int) (*Member, error) {
	if e == nil || e.inner == nil {
		return nil, ErrUninitializedEra
	}
	if index < 0 || index >= len(e.inner.State.Validators) {
		return nil, fmt.Errorf("%w: index %d out of range [0,%d)", ErrUnknownMember, index, len(e.inner.State.Validators))
	}
	v := e.inner.State.Validators[index]
	ks, ok := e.inner.State.Shares[v]
	if !ok || ks == nil {
		return nil, fmt.Errorf("%w: %q", ErrUnknownMember, v)
	}
	return &Member{index: index, share: ks}, nil
}

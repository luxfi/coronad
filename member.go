// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package coronad

import (
	"github.com/luxfi/corona/threshold"

	"github.com/luxfi/lattice/v7/ring"
)

// Member is one committee member's signing identity: its 0-indexed committee
// position and its OWN secret key share. A Member never holds another member's
// secret share — this is the unit that makes the SigningSession no-reconstruct.
type Member struct {
	index int
	share *threshold.KeyShare
}

// Index is the member's 0-indexed committee position. The member's Shamir share
// lives at evaluation point Index+1 (corona's 1-indexed Shamir convention).
func (m *Member) Index() int { return m.index }

// sessionSigner builds a kernel Signer for this member for ONE session, with
// the supplied active-set Lagrange coefficient swapped in.
//
// The coefficient is PUBLIC (a Lagrange basis value over the participant set),
// not secret. The member's secret SkShare, pairwise Seeds and MACKeys are
// carried by reference into the per-session KeyShare and never leave the
// member; only the Lambda is replaced so the share reconstructs correctly for
// whatever t-of-n subset is actually signing. For the full committee this
// reproduces the coefficient keyera baked at Bootstrap.
//
// lambda MUST already be in NTT + Montgomery form (see lagrangeForSet) — the
// form the kernel's sign.Party expects for Lambda.
func (m *Member) sessionSigner(lambda ring.Poly) *threshold.Signer {
	sessionShare := &threshold.KeyShare{
		Index:    m.share.Index,
		SkShare:  m.share.SkShare,
		Seeds:    m.share.Seeds,
		MACKeys:  m.share.MACKeys,
		Lambda:   lambda,
		GroupKey: m.share.GroupKey,
	}
	return threshold.NewSigner(sessionShare)
}

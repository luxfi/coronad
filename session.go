// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package coronad

import (
	"fmt"
	"math/big"
	"sort"
	"sync"

	"github.com/luxfi/corona/primitives"
	"github.com/luxfi/corona/sign"
	"github.com/luxfi/corona/threshold"

	"github.com/luxfi/lattice/v7/ring"
)

// SigningSession drives ONE Corona 2-round threshold-signing session over a
// fixed message with a fixed participant set. It is warp-agnostic: message is
// the already-derived signing bytes (the Signer derives them via
// warp.CoronaSigningBytes), so the protocol core has no dependency on the warp
// wire format.
type SigningSession struct {
	era          *Era
	participants []int // sorted, distinct, 0-indexed committee positions; |.| >= t
	sessionID    int
	message      string
	prfKey       []byte
}

// NewSigningSession validates the participant set against the era and returns a
// session ready to Run. participants must be distinct committee positions in
// [0, n); at least t of them are required (true t-of-n: any >= t subset signs).
func NewSigningSession(era *Era, participants []int, sessionID int, message string, prfKey []byte) (*SigningSession, error) {
	if era == nil || era.inner == nil || era.GroupKey() == nil {
		return nil, ErrUninitializedEra
	}
	clean, err := normalizeParticipants(participants, era.Size())
	if err != nil {
		return nil, err
	}
	if len(clean) < era.Threshold() {
		return nil, fmt.Errorf("%w: have %d, need t=%d", ErrInsufficientParticipants, len(clean), era.Threshold())
	}
	return &SigningSession{
		era:          era,
		participants: clean,
		sessionID:    sessionID,
		message:      message,
		prfKey:       prfKey,
	}, nil
}

// Run executes the session over tr and returns the aggregated Corona threshold
// signature. Each participant runs in its own goroutine and exchanges the two
// rounds via tr; the lowest-indexed participant is the deterministic combiner.
//
// No-reconstruct: every goroutine operates on its own Member's share; the only
// data crossing tr is the public Round1Data / Round2Data, and Finalize consumes
// only the public z partials. A secret share is never centralized.
func (s *SigningSession) Run(tr Transport) (*threshold.Signature, error) {
	r := s.era.GroupKey().Params.R

	// Recompute the Lagrange coefficients for the ACTIVE participant set so any
	// t-of-n subset interpolates s correctly. This is the single signing path;
	// for the full committee it reproduces keyera's baked coefficients.
	lambdas := lagrangeForSet(r, s.participants)

	combiner := s.participants[0] // deterministic: lowest participant index

	var (
		mu       sync.Mutex
		firstErr error
		sig      *threshold.Signature
		wg       sync.WaitGroup
	)
	fail := func(err error) {
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
		tr.Abort(err) // release the other members blocked at a barrier
	}

	for _, idx := range s.participants {
		wg.Go(func() {
			member, err := s.era.Member(idx)
			if err != nil {
				fail(err)
				return
			}
			signer := member.sessionSigner(lambdas[idx])

			// Round 1: masked commitment D + pairwise MACs.
			r1, err := signer.Round1(s.sessionID, s.prfKey, s.participants)
			if err != nil {
				fail(fmt.Errorf("participant %d round1: %w", idx, err))
				return
			}
			all1, err := tr.Round1(idx, r1)
			if err != nil {
				fail(err)
				return
			}

			// Round 2: z partial (verifies peers' MACs, computes shared c/H).
			r2, err := signer.Round2(s.sessionID, s.message, s.prfKey, s.participants, all1)
			if err != nil {
				fail(fmt.Errorf("participant %d round2: %w", idx, err))
				return
			}
			all2, err := tr.Round2(idx, r2)
			if err != nil {
				fail(err)
				return
			}

			// Finalize: only the combiner aggregates (any party could — c/H are
			// identical across the committee — but one signature suffices).
			if idx == combiner {
				out, err := signer.Finalize(all2)
				if err != nil {
					fail(fmt.Errorf("combiner %d finalize: %w", idx, err))
					return
				}
				mu.Lock()
				sig = out
				mu.Unlock()
			}
		})
	}
	wg.Wait()

	if firstErr != nil {
		return nil, firstErr
	}
	if sig == nil {
		return nil, ErrNoSignature
	}
	return sig, nil
}

// lagrangeForSet returns the NTT+Montgomery-form Lagrange coefficient for each
// participant, keyed by committee index. participants is sorted/distinct.
//
// primitives.ComputeLagrangeCoefficients maps a 0-indexed committee position p
// to Shamir evaluation point p+1, matching how corona shares are dealt, and
// returns a slice positionally aligned with the input. We then NTT+MForm each
// coefficient — the form sign.Party.Lambda requires — exactly as keyera does.
func lagrangeForSet(r *ring.Ring, participants []int) map[int]ring.Poly {
	modulus := new(big.Int).SetUint64(sign.Q)
	coeffs := primitives.ComputeLagrangeCoefficients(r, participants, modulus)
	out := make(map[int]ring.Poly, len(participants))
	for p, idx := range participants {
		lambda := r.NewPoly()
		lambda.Copy(coeffs[p])
		r.NTT(lambda, lambda)
		r.MForm(lambda, lambda)
		out[idx] = lambda
	}
	return out
}

// normalizeParticipants validates and returns a sorted, distinct copy of the
// participant indices, each in [0, n).
func normalizeParticipants(participants []int, n int) ([]int, error) {
	if len(participants) == 0 {
		return nil, fmt.Errorf("%w: empty", ErrBadParticipants)
	}
	seen := make(map[int]struct{}, len(participants))
	clean := make([]int, 0, len(participants))
	for _, idx := range participants {
		if idx < 0 || idx >= n {
			return nil, fmt.Errorf("%w: index %d out of range [0,%d)", ErrBadParticipants, idx, n)
		}
		if _, dup := seen[idx]; dup {
			return nil, fmt.Errorf("%w: duplicate index %d", ErrBadParticipants, idx)
		}
		seen[idx] = struct{}{}
		clean = append(clean, idx)
	}
	sort.Ints(clean)
	return clean, nil
}

// fullCommittee returns [0, 1, ..., n-1] for the era's committee.
func fullCommittee(era *Era) []int {
	out := make([]int, era.Size())
	for i := range out {
		out[i] = i
	}
	return out
}

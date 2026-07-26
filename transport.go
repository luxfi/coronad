// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package coronad

import "github.com/luxfi/corona/threshold"

// Transport is the committee round-transport: it carries the two broadcast
// rounds of the Corona signing protocol among the participating members. Each
// round is an all-gather — a member publishes its own message and receives the
// full set (its own included), blocking until every participant has published.
//
// The transport carries only PUBLIC protocol messages (Round1Data = masked
// commitments + MACs; Round2Data = z partials). It never carries a secret
// share — that is the structural reason the signing protocol is no-reconstruct.
//
// A Transport instance is SESSION-SCOPED: it is used for exactly one signing
// session (one Round1 all-gather followed by one Round2 all-gather). Build a
// fresh one per session via a TransportFactory.
type Transport interface {
	// Round1 publishes self's Round1Data and returns the collected Round1Data
	// from every participant, keyed by PartyID. Blocks until the full
	// participant set has published, or returns a non-nil error if the session
	// was aborted.
	Round1(self int, out *threshold.Round1Data) (map[int]*threshold.Round1Data, error)

	// Round2 is the symmetric all-gather for Round2Data.
	Round2(self int, out *threshold.Round2Data) (map[int]*threshold.Round2Data, error)

	// Abort tears the session transport down with err, releasing any members
	// blocked in Round1/Round2 with that error. Idempotent. Called by the
	// session when any member fails, so a single fault cannot deadlock the
	// remaining members at a barrier.
	Abort(err error)
}

// TransportFactory builds a fresh session-scoped Transport for the given
// participant set. Loopback is the in-process implementation.
type TransportFactory func(participants []int) Transport

// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package coronad

import "errors"

// Sentinel errors. They are wrapped with %w throughout so callers can match
// with errors.Is and fail closed.
var (
	// ErrUninitializedEra is returned when an Era has no GroupKey / share
	// state — i.e. it was not produced by Bootstrap.
	ErrUninitializedEra = errors.New("coronad: era is uninitialized")

	// ErrInsufficientParticipants is returned when fewer than the era's
	// threshold t members are asked to sign. The corona protocol cannot
	// produce a verifying signature below t.
	ErrInsufficientParticipants = errors.New("coronad: fewer participants than threshold")

	// ErrBadParticipants is returned when the participant set is malformed:
	// out-of-range index, duplicate, or empty.
	ErrBadParticipants = errors.New("coronad: invalid participant set")

	// ErrUnknownMember is returned when a committee position has no share in
	// the era's state.
	ErrUnknownMember = errors.New("coronad: unknown committee member")

	// ErrNoSignature is returned when a signing session completed without the
	// combiner producing a signature (should be unreachable on the success
	// path; present as a fail-closed guard).
	ErrNoSignature = errors.New("coronad: session produced no signature")

	// ErrSelfVerifyFailed is the fail-closed gate: coronad NEVER emits
	// evidence whose signature does not verify under the era's group key.
	ErrSelfVerifyFailed = errors.New("coronad: self-verify failed; refusing to emit evidence")

	// ErrTransportAborted is returned by Transport round calls after the
	// session aborted (e.g. a member failed Round1/Round2).
	ErrTransportAborted = errors.New("coronad: transport aborted")

	// ErrBadSubject is returned when ThresholdSign is given a subject that is
	// not a 32-byte finality digest.
	ErrBadSubject = errors.New("coronad: subject must be a 32-byte digest")
)

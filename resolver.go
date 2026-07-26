// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package coronad

import (
	"fmt"
	"sync"

	"github.com/luxfi/corona/threshold"
	"github.com/luxfi/ids"
	"github.com/luxfi/warp"

	warppulsar "github.com/luxfi/warp/pulsar"
)

// EraResolver is an in-memory warp/pulsar.CoronaGroupKeyResolver: it maps a
// (chainID, keyEraID, generation) tuple to the era's Corona group key and the
// Corona suite id. A destination chain's REAL resolver pulls the group key from
// its on-chain source-chain Corona key registry; EraResolver is the same shape
// for tests and single-box deployment.
//
// Compile-time assertion that *EraResolver satisfies the warp boundary:
var _ warppulsar.CoronaGroupKeyResolver = (*EraResolver)(nil)

type eraKey struct {
	chainID    ids.ID
	keyEraID   uint64
	generation uint64
}

type EraResolver struct {
	mu   sync.RWMutex
	keys map[eraKey]*threshold.GroupKey
}

// NewEraResolver returns an empty resolver. Register eras with Add.
func NewEraResolver() *EraResolver {
	return &EraResolver{keys: make(map[eraKey]*threshold.GroupKey)}
}

// Add registers an era's group key for its CURRENT (chainID, keyEraID,
// generation). Corona's Reshare/Refresh preserve the group key but advance the
// generation, so call Add again after each advance to answer for the new
// generation the emitted evidence carries.
func (r *EraResolver) Add(era *Era) {
	if era == nil || era.GroupKey() == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys[eraKey{era.ChainID(), era.KeyEraID(), era.Generation()}] = era.GroupKey()
}

// ResolveGroupKey implements warp/pulsar.CoronaGroupKeyResolver.
func (r *EraResolver) ResolveGroupKey(sourceChainID [32]byte, keyEraID, generation uint64) (*threshold.GroupKey, string, error) {
	r.mu.RLock()
	gk, ok := r.keys[eraKey{ids.ID(sourceChainID), keyEraID, generation}]
	r.mu.RUnlock()
	if !ok || gk == nil {
		return nil, "", fmt.Errorf("coronad: no Corona group key for chain=%x keyEra=%d gen=%d",
			sourceChainID[:4], keyEraID, generation)
	}
	return gk, string(warp.DefaultCoronaSuiteID), nil
}

// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package coronad

import (
	"fmt"
	"sync"

	"github.com/luxfi/corona/threshold"
)

// Loopback is the TransportFactory for the in-process transport. It models a
// committee whose members run concurrently (one goroutine each) and exchange
// the two signing rounds over a barrier-synchronized all-gather — faithful to a
// distributed deployment, but with no sockets. Production wraps the corona
// kernel's networking (ZAP P2P) behind the same Transport interface.
func Loopback(participants []int) Transport {
	return newLoopbackTransport(participants)
}

// LoopbackTransport is one session's in-process transport. It holds two
// all-gather barriers (Round1, Round2) sized to the participant count and a
// shared abort signal so a single member fault releases the rest.
type LoopbackTransport struct {
	abort     chan struct{}
	abortErr  error
	abortMu   sync.Mutex
	abortOnce sync.Once

	r1 *gather[*threshold.Round1Data]
	r2 *gather[*threshold.Round2Data]
}

func newLoopbackTransport(participants []int) *LoopbackTransport {
	want := len(participants)
	abort := make(chan struct{})
	t := &LoopbackTransport{abort: abort}
	t.r1 = newGather[*threshold.Round1Data](want, abort)
	t.r2 = newGather[*threshold.Round2Data](want, abort)
	return t
}

// Round1 implements Transport.
func (t *LoopbackTransport) Round1(self int, out *threshold.Round1Data) (map[int]*threshold.Round1Data, error) {
	return t.r1.submit(self, out, t.abortError)
}

// Round2 implements Transport.
func (t *LoopbackTransport) Round2(self int, out *threshold.Round2Data) (map[int]*threshold.Round2Data, error) {
	return t.r2.submit(self, out, t.abortError)
}

// Abort implements Transport. Idempotent: the first caller's error is the one
// blocked members observe.
func (t *LoopbackTransport) Abort(err error) {
	t.abortOnce.Do(func() {
		t.abortMu.Lock()
		t.abortErr = err
		t.abortMu.Unlock()
		close(t.abort)
		// Wake any members blocked at either barrier so they observe the abort
		// instead of deadlocking.
		t.r1.wake()
		t.r2.wake()
	})
}

func (t *LoopbackTransport) abortError() error {
	t.abortMu.Lock()
	defer t.abortMu.Unlock()
	if t.abortErr != nil {
		return t.abortErr
	}
	return ErrTransportAborted
}

// gather is a single-round all-gather barrier over a generic payload. Members
// submit their payload keyed by id; submit blocks until `want` distinct ids
// have been collected, then returns a copy of the full map to every caller.
type gather[T any] struct {
	mu    sync.Mutex
	cond  *sync.Cond
	want  int
	items map[int]T
	abort chan struct{}
}

func newGather[T any](want int, abort chan struct{}) *gather[T] {
	g := &gather[T]{want: want, items: make(map[int]T, want), abort: abort}
	g.cond = sync.NewCond(&g.mu)
	return g
}

func (g *gather[T]) submit(id int, v T, abortErr func() error) (map[int]T, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.aborted() {
		return nil, abortErr()
	}
	if _, dup := g.items[id]; dup {
		return nil, fmt.Errorf("%w: duplicate submission from participant %d", ErrBadParticipants, id)
	}
	g.items[id] = v
	g.cond.Broadcast() // a new arrival may complete the barrier for others

	for len(g.items) < g.want {
		if g.aborted() {
			return nil, abortErr()
		}
		g.cond.Wait()
	}
	if g.aborted() {
		return nil, abortErr()
	}

	out := make(map[int]T, len(g.items))
	for k, val := range g.items {
		out[k] = val
	}
	return out, nil
}

// aborted reports whether the shared abort signal is closed. Caller holds g.mu.
func (g *gather[T]) aborted() bool {
	select {
	case <-g.abort:
		return true
	default:
		return false
	}
}

// wake broadcasts to release waiters (used by Abort).
func (g *gather[T]) wake() {
	g.mu.Lock()
	g.cond.Broadcast()
	g.mu.Unlock()
}

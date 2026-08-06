// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Carles Ortega Ragull (ragull, socat, carles) <ragull@socket.cat>

// Package ringbuf implements a bounded ring buffer of byte chunks used to
// retain recent terminal output for late-joining WebSocket clients.
//
// It is a fixed-capacity circular store that grows geometrically, evicting the oldest
// chunk once either the total byte budget (maxBytes) or the hard entry cap
// (MaxCount) is exceeded.
package ringbuf

const MaxCount = 10000

// Buffer holds recently-pushed byte chunks in FIFO order.
type Buffer struct {
	chunks    [][]byte
	chunkSize []int
	cap       int
	head      int
	tail      int
	size      int
	byteTotal int
	maxBytes  int
}

// New returns a ring buffer that will evict down to at most one entry once
// the cumulative stored data reaches maxBytes.
func New(maxBytes int) *Buffer {
	if maxBytes <= 0 {
		panic("ringbuf: maxBytes must be a positive number")
	}
	rb := &Buffer{cap: 512, maxBytes: maxBytes}
	rb.chunks = make([][]byte, rb.cap)
	rb.chunkSize = make([]int, rb.cap)
	return rb
}

// Push appends data (with its precomputed byte length) and returns true if at
// least one older chunk was evicted to satisfy the budget.
func (rb *Buffer) Push(data []byte, byteSize int) bool {
	rb.ensureCapacity(rb.size + 1)
	rb.chunks[rb.tail] = data
	rb.chunkSize[rb.tail] = byteSize
	rb.tail = (rb.tail + 1) % rb.cap
	rb.size++
	rb.byteTotal += byteSize

	evicted := false
	for (rb.byteTotal >= rb.maxBytes || rb.size > MaxCount) && rb.size > 1 {
		rb.evictOne()
		evicted = true
	}
	return evicted
}

// Shift removes and returns the oldest entry, or nil when empty.
func (rb *Buffer) Shift() []byte {
	if rb.size == 0 {
		return nil
	}
	data := rb.chunks[rb.head]
	rb.byteTotal -= rb.chunkSize[rb.head]
	rb.chunks[rb.head] = nil
	rb.chunkSize[rb.head] = 0
	rb.head = (rb.head + 1) % rb.cap
	rb.size--
	return data
}

// Len returns the number of stored chunks.
func (rb *Buffer) Len() int { return rb.size }

// Snapshot returns all chunks as a fresh slice. Safe to retain after mutation.
func (rb *Buffer) Snapshot() [][]byte {
	out := make([][]byte, 0, rb.size)
	for i, idx := 0, rb.head; i < rb.size; i, idx = i+1, (idx+1)%rb.cap {
		out = append(out, rb.chunks[idx])
	}
	return out
}

func (rb *Buffer) evictOne() {
	rb.byteTotal -= rb.chunkSize[rb.head]
	rb.chunks[rb.head] = nil
	rb.chunkSize[rb.head] = 0
	rb.head = (rb.head + 1) % rb.cap
	rb.size--
}

func (rb *Buffer) ensureCapacity(minCap int) {
	if rb.cap >= minCap {
		return
	}
	oldCap := rb.cap
	newCap := oldCap
	for newCap < minCap {
		newCap *= 2
	}
	newChunks := make([][]byte, newCap)
	newSizes := make([]int, newCap)
	for i := 0; i < rb.size; i++ {
		srcIdx := (rb.head + i) % oldCap
		newChunks[i] = rb.chunks[srcIdx]
		newSizes[i] = rb.chunkSize[srcIdx]
	}
	rb.chunks = newChunks
	rb.chunkSize = newSizes
	rb.cap = newCap
	rb.head = 0
	rb.tail = rb.size
}

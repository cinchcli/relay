package main

import (
	"errors"
	"sync/atomic"
)

var ErrBusy = errors.New("another operation is in progress")

type state struct {
	running atomic.Bool
}

func (s *state) tryLock() bool {
	return s.running.CompareAndSwap(false, true)
}

func (s *state) unlock() {
	s.running.Store(false)
}

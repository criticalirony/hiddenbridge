package utils

import (
	"container/list"
	"context"
	"errors"
	"sync"
	"time"
)

var (
	ErrLockBusy    = errors.New("lock busy")
	ErrLockTimeout = errors.New("lock timeout")
)

type Lock struct {
	locked  bool
	mu      sync.Mutex
	waiters list.List
}

func (l *Lock) Acquire(ctx context.Context) error {
	if l == nil {
		return nil // We can always acquire a nil lock
	}

	l.mu.Lock()

	if !l.locked && l.waiters.Len() == 0 {
		l.locked = true
		l.mu.Unlock()
		return nil
	}

	ready := make(chan struct{})
	elem := l.waiters.PushBack(ready)
	l.mu.Unlock()

	select {
	case <-ctx.Done():
		err := ctx.Err()
		l.mu.Lock()
		select {
		case <-ready: // we acquired lock after cancel, ignore cancel
			err = nil
		default:
			isFront := l.waiters.Front() == elem
			l.waiters.Remove(elem)
			if isFront {
				l.notifyWaiters()
			}
		}
		l.mu.Unlock()
		return err
	case <-ready:
		return nil
	}
}

func (l *Lock) TryAcquire() bool {
	l.mu.Lock()
	success := !l.locked && l.waiters.Len() == 0
	if success {
		l.locked = true
	}
	l.mu.Unlock()
	return success
}

func (l *Lock) AcquireWithTimeout(timeout time.Duration) error {
	if l == nil {
		return nil // We can always acquire a nil lock
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	err := l.Acquire(ctx)
	if err != nil && errors.Is(err, context.DeadlineExceeded) {
		err = ErrLockTimeout
	}

	return err
}

func (l *Lock) IsLocked() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.locked
}

func (l *Lock) Release() {
	if l == nil {
		return // We can always release a nil lock
	}

	l.mu.Lock()
	l.locked = false
	l.notifyWaiters()
	l.mu.Unlock()
}

func (l *Lock) notifyWaiters() {
	if l.locked {
		return
	}

	next := l.waiters.Front()
	if next == nil {
		return
	}

	w := next.Value.(chan struct{})
	l.waiters.Remove(next)
	l.locked = true
	close(w)
}

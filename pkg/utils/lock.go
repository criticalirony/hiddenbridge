package utils

import (
	"context"
	"errors"
	"time"

	"golang.org/x/xerrors"
)

var (
	ErrNotLocked = errors.New("not locked")
	ErrLockBusy  = errors.New("lock busy")
)

type Lock struct {
	ch chan struct{}
}

func NewLock() *Lock {
	l := &Lock{
		ch: make(chan struct{}, 1),
	}

	// Mark channel as unlocked
	l.ch <- struct{}{}

	return l
}

func (l *Lock) Lock() error {
	return l.LockWithContext(context.Background())
}

func (l *Lock) LockWithContext(ctx context.Context) error {
	select {
	case <-l.ch:
		return nil
	case <-ctx.Done():
		return xerrors.Errorf("lock with context cancelled: %w", ctx.Err())
	}
}

func (l *Lock) LockWithTimeout(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return l.LockWithContext(ctx)
}

func (l *Lock) UnLock() error {
	var err error

	select {
	case l.ch <- struct{}{}:
		err = nil
	default:
		err = xerrors.Errorf("failed to unlock: %w", ErrNotLocked)
	}

	return err
}

func (l *Lock) TryLock() error {

	select {
	case <-l.ch:
		return nil
	default:
		return xerrors.Errorf("failed to lock: %w", ErrLockBusy)
	}
}

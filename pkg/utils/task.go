package utils

import (
	"errors"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/xerrors"
)

var (
	ErrNoFunction = errors.New("no function")
)

type Task struct {
	lock   Lock
	Desc   string
	fn     func(ctx interface{}) error
	Ctx    interface{}
	isBusy bool
	Err    error
}

func NewTask(desc string, fn func(ctx interface{}) error) *Task {
	t := &Task{
		lock: *NewLock(),
		Desc: desc,
		fn:   fn,
	}

	return t
}

func (t *Task) Run(ctx interface{}) error {
	if t.fn == nil {
		return xerrors.Errorf("failed to run task: %w", ErrLockBusy)
	}

	if err := t.lock.TryLock(); err != nil {
		return xerrors.Errorf("failed to run task: %w", err)
	}

	t.Ctx = ctx

	started := make(chan struct{})
	go func() {
		t.isBusy = true
		close(started)
		t.Err = t.fn(ctx)
		t.isBusy = false
		if err := t.lock.UnLock(); err != nil {
			log.Err(err).Msg("task unlock failure")
		}
	}()

	<-started

	return nil
}

func (t *Task) IsBusy() bool {
	return t.isBusy
}

func (t *Task) Wait(timeout time.Duration) error {
	if !t.isBusy {
		return nil
	}

	defer t.lock.UnLock()

	if timeout <= 0 {
		if err := t.lock.Lock(); err != nil {
			return xerrors.Errorf("wait for task completion failure: %w", err)
		}
	} else if err := t.lock.LockWithTimeout(timeout); err != nil {
		return xerrors.Errorf("wait for task completion failure: %w", err)
	}

	return nil
}

func (t *Task) SetFunction(fn func(ctx interface{}) error) error {
	if err := t.lock.TryLock(); err != nil {
		return xerrors.Errorf("failed to set function: %w", ErrLockBusy)
	}

	defer t.lock.UnLock()

	t.fn = fn
	return nil
}

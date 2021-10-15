package utils

import (
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/xerrors"
)

var (
	ErrNoFunction = errors.New("no function")
)

type ErrExpiry struct {
	expires time.Time
}

func NewErrExpiryOn(expire time.Time) ErrExpiry {
	return ErrExpiry{expires: expire}
}

func NewErrExpiryAfter(dur time.Duration) ErrExpiry {
	return ErrExpiry{expires: time.Now().UTC().Add(dur)}
}

func (e ErrExpiry) Error() string {
	now := time.Now().UTC()
	if now.After(e.expires) {
		return fmt.Sprintf("expired: %s", e.expires.String())
	}

	return fmt.Sprintf("not expired: expires %s: %s", e.expires.String(), e.expires.Sub(now).String())
}

func (e ErrExpiry) Expires() time.Time {
	return e.expires
}

func (e ErrExpiry) Expired() bool {
	return time.Now().UTC().After(e.expires)
}

type Task struct {
	lock    Lock
	Desc    string
	Ctx     interface{}
	Err     error
	fn      func(ctx interface{}) error
	isBusy  bool
	lastRun time.Time
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
		return xerrors.Errorf("failed to run task: %w", ErrNoFunction)
	}

	if err := t.lock.TryLock(); err != nil {
		return xerrors.Errorf("failed to run task: %w", err)
	}

	t.Ctx = ctx

	started := make(chan struct{})
	go func() {
		t.isBusy = true
		close(started)
		t.lastRun = time.Now().UTC()
		log.Debug().Msgf("task: %v started: %s", t.fn, t.lastRun)
		t.Err = t.fn(ctx)
		t.isBusy = false
		startRun := t.lastRun
		t.lastRun = time.Now().UTC()
		log.Debug().Msgf("task: %v completed: %s (%s)", t.fn, t.lastRun, t.lastRun.Sub(startRun))

		if err := t.lock.UnLock(); err != nil {
			log.Err(err).Msg("task unlock failure")
		}

		if t.Err != nil {
			// Uncomment below for stack trace of error
			// log.Error().Msgf("task run failure: %+v", t.Err)
			log.Error().Msgf("task run failure: %v", t.Err)
		}
	}()

	<-started

	return nil
}

func (t *Task) RunIfOlder(ctx interface{}, dur time.Duration) error {
	taskAgeOff := t.lastRun.Add(dur)
	if time.Now().UTC().Before(taskAgeOff) {
		return xerrors.Errorf("task run failure: %w", NewErrExpiryOn(taskAgeOff))
	}

	return t.Run(ctx)
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

package utils

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/xerrors"
)

var (
	ErrTaskBusy       = errors.New("task busy")
	ErrTaskNotExpired = errors.New("task not expired")
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
	Name      string
	RunCtx    interface{}
	Err       error
	fn        func(ctx interface{}) error
	fnDoneCB  func(task *Task, runctx interface{}, err error)
	completed chan struct{}
}

func TaskDefaultDoneCB(task *Task, runctx interface{}, err error) {
	if err != nil {
		log.Error().Err(err).Msgf("task: %+v failure", task)
	}
}

func NewTask(name string, fn func(ctx interface{}) error, cb func(task *Task, runctx interface{}, err error)) *Task {
	t := &Task{
		Name:     name,
		fn:       fn,
		fnDoneCB: cb,
	}

	if t.fnDoneCB == nil {
		t.fnDoneCB = TaskDefaultDoneCB
	}

	return t
}

func (t *Task) Run(ctx interface{}) error {
	if t.IsBusy() {
		return ErrTaskBusy
	}

	t.RunCtx = ctx

	started := make(chan struct{})
	t.completed = make(chan struct{})
	go func() {
		defer close(t.completed)
		close(started)
		if t.fn != nil {
			t.Err = t.fn(t.RunCtx)
		}
		if t.fnDoneCB != nil {
			t.fnDoneCB(t, t.RunCtx, t.Err)
		}
	}()

	<-started

	return nil
}

func (t *Task) IsBusy() bool {
	if t.completed == nil {
		return false
	}

	select {
	case <-t.completed:
		return false
	default:
		return true
	}
}

func (t *Task) Wait(timeout time.Duration) error {
	if !t.IsBusy() {
		return nil
	}

	var (
		ctx    context.Context
		cancel context.CancelFunc
	)

	if timeout <= 0 {
		ctx, cancel = context.WithCancel(context.Background())
	} else {
		ctx, cancel = context.WithTimeout(context.Background(), timeout)
	}

	defer cancel()

	select {
	case <-ctx.Done():
		return xerrors.Errorf("wait for task completion failure: %w", ctx.Err())
	case <-t.completed:
		return nil
	}
}

func (t *Task) SetFunction(fn func(ctx interface{}) error) {
	t.fn = fn
}

func (t *Task) SetCompletedCB(fn func(task *Task, runctx interface{}, err error)) {
	t.fnDoneCB = fn
}

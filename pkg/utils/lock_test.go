package utils

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"
)

func TestSimpleLock(t *testing.T) {
	var (
		err  error
		lock *Lock
	)

	lock = NewLock()
	err = lock.Lock()
	require.Nil(t, err)

	go func() {
		time.Sleep(1 * time.Second)
		err := lock.UnLock()
		require.Nil(t, err)
	}()

	start := time.Now().UTC()
	err = lock.Lock()
	require.Nil(t, err)
	duration := time.Now().UTC().Sub(start)
	require.True(t, duration >= 1*time.Second, "lock only held for: %s", duration)

	err = lock.UnLock()
	require.Nil(t, err)

	err = lock.UnLock()
	require.Equal(t, ErrNotLocked, xerrors.Unwrap(err))
}

func TestSimpleTryLock(t *testing.T) {
	var (
		err  error
		lock *Lock
	)

	lock = NewLock()
	err = lock.Lock()
	require.Nil(t, err)

	go func() {
		time.Sleep(1 * time.Second)
		err := lock.UnLock()
		require.Nil(t, err)
	}()

	err = lock.TryLock()
	require.Equal(t, ErrLockBusy, xerrors.Unwrap(err))

	err = lock.UnLock()
	require.Nil(t, err)

	err = lock.TryLock()
	require.Nil(t, err)

	err = lock.UnLock()
	require.Nil(t, err)
}

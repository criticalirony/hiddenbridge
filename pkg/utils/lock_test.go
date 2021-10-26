package utils

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSimpleLock(t *testing.T) {
	var (
		err error
	)

	lock := &Lock{}
	err = lock.Acquire(context.Background())
	require.Nil(t, err)
	require.True(t, lock.IsLocked())

	go func() {
		time.Sleep(1 * time.Second)
		lock.Release()
	}()

	err = lock.AcquireWithTimeout(500 * time.Millisecond)
	require.Equal(t, ErrLockTimeout, err)

	time.Sleep(1 * time.Second)
	require.False(t, lock.IsLocked())
}

func TestSimpleTryLock(t *testing.T) {
	var (
		err  error
		lock *Lock
	)

	ctx := context.Background()

	lock = &Lock{}
	err = lock.Acquire(ctx)
	require.Nil(t, err)

	go func() {
		time.Sleep(1 * time.Second)
		lock.Release()
	}()

	require.False(t, lock.TryAcquire())

	lock.Release()
	require.True(t, lock.TryAcquire())

	lock.Release()
}

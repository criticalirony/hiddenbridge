package utils

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSimpleTask(t *testing.T) {
	output := &strings.Builder{}

	task := NewTask("task1", nil)
	task.SetFunction(func(ctx interface{}) error {
		output := ctx.(*strings.Builder)
		output.WriteString("I'm a simple task")
		return nil
	})

	err := task.Run(output)
	require.Nil(t, err)

	err = task.Wait(0)
	require.Nil(t, err)
	require.Equal(t, "I'm a simple task", output.String())
}

func TestBusyTask(t *testing.T) {
	output := &strings.Builder{}

	task := NewTask("task1", nil)
	task.SetFunction(func(ctx interface{}) error {
		output := ctx.(*strings.Builder)

		for i := 0; i < 3; i++ {
			time.Sleep(500 * time.Millisecond)
			output.WriteString(fmt.Sprintf("I'm a simple task: %d\n", i))
		}

		return nil
	})

	err := task.Run(output)
	require.Nil(t, err)

	time.Sleep(500 * time.Millisecond)

	err = task.Run(output)
	require.True(t, task.IsBusy())
	require.True(t, errors.Is(err, ErrLockBusy))

	err = task.Wait(-1)
	require.Nil(t, err)
	require.False(t, task.IsBusy())
	require.Equal(t, "I'm a simple task: 0\nI'm a simple task: 1\nI'm a simple task: 2\n", output.String())
}

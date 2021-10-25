package command

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCommandSimple(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out, err := Run(ctx, "", nil, "/bin/bash", "-c", "ls /tmp")
	require.Nil(t, err)
	require.Greater(t, len(out), 0)
}

func TestCommandEnviron(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out, err := Run(ctx, "", NewEnvs("TEST_VAR=hello world"), "/bin/bash", "-c", "echo -n $TEST_VAR")
	require.Nil(t, err)
	require.Equal(t, "hello world", string(out))
}

func TestCommandWorkingDir(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	pwd, err := os.Getwd()
	require.Nil(t, err)

	out, err := Run(ctx, "", nil, "/bin/bash", "-c", "echo -n $PWD")
	require.Nil(t, err)
	require.Equal(t, pwd, string(out))

	out, err = Run(ctx, "/tmp", nil, "/bin/bash", "-c", "echo -n $PWD")
	require.Nil(t, err)
	require.Equal(t, "/tmp", string(out))
}

func TestCommandTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err := Run(ctx, "", nil, "/bin/bash", "-c", "sleep 5")
	require.NotNil(t, err)
	require.Equal(t, "/bin/bash -c sleep 5 in : signal: killed", err.Error())

	err = errors.Unwrap(err)
	require.NotNil(t, err)

	exitErr := &exec.ExitError{}
	require.True(t, errors.Is(err, context.DeadlineExceeded) || errors.As(err, &exitErr))
}

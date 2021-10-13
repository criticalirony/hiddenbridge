package command

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"
)

func TestCommandSimple(t *testing.T) {
	cmd := NewCommand("/bin/bash", "-c", "ls /tmp")

	stdout := &strings.Builder{}
	stderr := &strings.Builder{}

	err := cmd.Run(2*time.Second, stdout, stderr, "")
	require.Nil(t, err)
	require.Greater(t, len(stdout.String()), 0)
	require.Equal(t, len(stderr.String()), 0)
}

func TestCommandEnviron(t *testing.T) {
	cmd := NewCommand("/bin/bash", "-c", "echo -n $TEST_VAR")
	cmd.AddEnv("TEST_VAR=hello world")
	stdout := &strings.Builder{}
	stderr := &strings.Builder{}

	err := cmd.Run(2*time.Second, stdout, stderr, "")
	require.Nil(t, err)
	require.Equal(t, len(stderr.String()), 0)
	require.Equal(t, "hello world", stdout.String())

}

func TestCommandWorkingDir(t *testing.T) {
	cmd := NewCommand("/bin/bash", "-c", "echo -n $PWD")
	stdout := &strings.Builder{}
	stderr := &strings.Builder{}

	pwd, err := os.Getwd()
	require.Nil(t, err)

	err = cmd.Run(2*time.Second, stdout, stderr, "")
	require.Nil(t, err)
	require.Equal(t, len(stderr.String()), 0)
	require.Equal(t, pwd, stdout.String())

	cmd = NewCommand("/bin/bash", "-c", "echo -n $PWD")
	stdout = &strings.Builder{}
	stderr = &strings.Builder{}

	err = cmd.Run(2*time.Second, stdout, stderr, "/tmp")
	require.Nil(t, err)
	require.Equal(t, "/tmp", stdout.String())
}

func TestCommandTimeout(t *testing.T) {
	cmd := NewCommand("/bin/bash", "-c", "sleep 5")
	stdout := &strings.Builder{}
	stderr := &strings.Builder{}

	err := cmd.Run(500*time.Millisecond, stdout, stderr, "")
	require.Equal(t, context.DeadlineExceeded, xerrors.Unwrap(err))
}

// Copied from: https://github.com/gogs/gogs.git

package command

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/xerrors"
)

// Command contains the name, arguments and environment variables of a command.
type Command struct {
	name string
	args []string
	envs map[string]string
}

func NewCommand(name string, args ...string) *Command {
	return &Command{
		name: name,
		args: args,
	}
}

func (c *Command) AddArgs(args ...string) {
	c.args = append(c.args, args...)
}

func (c *Command) AddEnv(envs ...string) {
	if c.envs == nil {
		c.envs = map[string]string{}
	}

	for _, env := range envs {
		envParts := strings.SplitN(env, "=", 2)
		if len(envParts) == 0 {
			continue
		}

		key := envParts[0]
		value := ""
		if len(envParts) > 1 {
			value = envParts[1]
		}

		c.envs[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
}

func (c *Command) Envs() []string {
	res := []string{}

	// c.envs can be nil. This is ok because enumeration on nil objects is just zero length
	for k, v := range c.envs {
		res = append(res, k+"="+v)
	}

	return res
}

func (c *Command) Run(timeout time.Duration, stdout, stderr io.Writer, dir string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer func() {
		cancel()
	}()

	cmd := exec.CommandContext(ctx, c.name, c.args...)
	cmd.Env = append(os.Environ()[:], c.Envs()...)
	cmd.Dir = dir
	cmd.Stderr = stderr
	cmd.Stdout = stdout
	if err = cmd.Start(); err != nil {
		return xerrors.Errorf("%+v failed to start: %w", c, err)
	}

	result := make(chan error)
	go func() {
		result <- cmd.Wait()
	}()

	select {
	case <-ctx.Done():
		<-result

		isExited := cmd.ProcessState.Exited()
		if waitstatus, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
			isExited = isExited || waitstatus.Signaled()
		}

		if cmd.Process != nil && cmd.ProcessState != nil && !isExited {
			if err = cmd.Process.Kill(); err != nil {
				xerrors.Errorf("kill process failure: %w", err)
			}
		}

		if err = ctx.Err(); err != nil {
			err = xerrors.Errorf("%+v completion failure: %w", c, err)
		}

	case err = <-result:
		if err != nil {
			err = xerrors.Errorf("%+v run failure: %w", c, err)
		}
	}

	return err
}

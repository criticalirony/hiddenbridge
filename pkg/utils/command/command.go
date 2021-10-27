package command

import (
	"bytes"
	"context"
	"hiddenbridge/pkg/utils"
	"io"
	"os/exec"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

// Exec 3rd party bins, heavily copied from:
// go/src/cmd/go/internal/modfetch/codehost/codehost.go
type RunError struct {
	Cmd      string
	Err      error
	Stderr   []byte
	HelpText string
}

func (e *RunError) Error() string {
	text := e.Cmd + ": " + e.Err.Error()
	stderr := bytes.TrimRight(e.Stderr, "\n")
	if len(stderr) > 0 {
		text += ":\n\t" + strings.ReplaceAll(string(stderr), "\n", "\n\t")
	}
	if len(e.HelpText) > 0 {
		text += "\n" + e.HelpText
	}
	return text
}

func (e *RunError) Unwrap() error {
	if e.Err != nil {
		return e.Err
	}

	return nil
}

var dirLock sync.Map

func Run(ctx context.Context, dir string, envs *Envs, cmdline ...interface{}) ([]byte, error) {
	return RunWithStdin(ctx, dir, nil, envs, cmdline...)
}

func RunWithStdin(ctx context.Context, dir string, stdin io.Reader, envs *Envs, cmdline ...interface{}) ([]byte, error) {
	if dir != "" {
		muIface, ok := dirLock.Load(dir)
		if !ok {
			muIface, _ = dirLock.LoadOrStore(dir, new(sync.Mutex))
		}
		mu := muIface.(*sync.Mutex)
		mu.Lock()
		defer mu.Unlock()
	}

	cmd := utils.StringList(cmdline...)

	var stderr bytes.Buffer
	var stdout bytes.Buffer

	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	c.Dir = dir
	c.Stdin = stdin
	c.Stderr = &stderr
	c.Stdout = &stdout

	if envs != nil {
		c.Env = append([]string{}, envs.StringList()...)
	}

	log.Debug().Msgf("cmd run: %s", c.String())

	err := c.Run()
	if err != nil {
		err = &RunError{Cmd: strings.Join(cmd, " ") + " in " + dir, Stderr: stderr.Bytes(), Err: err}
	}
	return stdout.Bytes(), err
}

// Command contains the name, arguments and environment variables of a command.

type Envs map[string]string

func NewEnvs(kvs ...string) *Envs {
	e := &Envs{}
	e.AddEnv(kvs...)
	return e
}

func (e Envs) AddEnv(envs ...string) {
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

		e[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
}

func (e Envs) StringList() []string {
	res := []string{}

	// c.envs can be nil. This is ok because enumeration on nil objects is just zero length
	for k, v := range e {
		res = append(res, k+"="+v)
	}

	return res
}

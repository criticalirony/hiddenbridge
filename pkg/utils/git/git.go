package git

import (
	"bytes"
	"errors"
	"fmt"
	"hiddenbridge/pkg/utils/command"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/mod/semver"
	"golang.org/x/xerrors"
)

const (
	minGitVer = "v1.8.3"
)

type Git struct {
	WorkingDir string
}

var (
	gitBin string

	versionRE = regexp.MustCompile(`(?im)^[^\d]*(\d+(?:\.\d+){0,2}).*$`)
	remoteRE  = regexp.MustCompile(`(?im)^.*?\s+(.*?)\s+.*$`)
)

func init() {
	var err error
	gitBin, err = exec.LookPath("git")
	if err != nil {
		log.Panic().Err(err).Msg("failed to find git executable")
	}

	gitBin, err = filepath.Abs(gitBin)
	if err != nil {
		log.Panic().Err(err).Msg("failed to git executable absolutepath")
	}
}

func AppPath() string {
	return gitBin
}

func Version() string {
	stdout := bytes.Buffer{}

	cmd := command.NewCommand(gitBin, "version")
	if err := cmd.Run(5*time.Second, &stdout, nil, ""); err != nil {
		log.Panic().Err(err).Msg("failed to get git executable version")
	}

	match := versionRE.FindStringSubmatch(stdout.String())
	version := "0"
	if len(match) > 0 {
		version = match[len(match)-1]
	}

	version = "v" + version

	if !semver.IsValid(version) {
		log.Panic().Msgf("git executable version: %s is not valid", version)
	}

	if semver.Compare(version, minGitVer) < 0 {
		log.Panic().Msgf("git executable version: %s is not supported", version)
	}

	return version
}

func Run(args []string, proxy, workingdir string, timeout time.Duration, stdout, stderr io.Writer) error {
	cmdArgs := []string{"-c", "http.sslVerify=false"}
	if proxy != "" {
		cmdArgs = append(cmdArgs, "-c", fmt.Sprintf("http.proxy=%s", proxy))
	}

	cmdArgs = append(cmdArgs, args...)
	cmd := command.NewCommand(gitBin, cmdArgs...)
	if err := cmd.Run(timeout, stdout, stderr, workingdir); err != nil {
		return xerrors.Errorf("failed to run git command: %w", err)
	}

	return nil
}

func Clone(repoURI, repoDir string, isBare, isMirror bool, proxy string, timeout time.Duration) error {
	args := []string{"clone", "-v"}

	if isMirror {
		args = append(args, "--mirror") // mirror implies bare
	} else if isBare {
		args = append(args, "--bare")
	}

	args = append(args, repoURI)

	if repoDir != "" {
		args = append(args, repoDir)
	}

	if err := Run(args, proxy, "", timeout, nil, nil); err != nil {
		return xerrors.Errorf("git clone failure: %w", err)
	}

	return nil
}

func Init(repoDir string, isBare bool, timeout time.Duration) error {
	args := []string{"init"}

	if isBare {
		args = append(args, "--bare")
	}

	args = append(args, repoDir)

	if err := Run(args, "", "", timeout, nil, nil); err != nil {
		return xerrors.Errorf("git init failure: %w", err)
	}

	return nil
}

func Remote(subcommand string, isPrune bool, gitdir string, proxy string, timeout time.Duration, stdout io.Writer) error {
	args := []string{"remote", "-v"}

	if subcommand != "" {
		args = append(args, subcommand)
	}

	if subcommand == "update" && isPrune {
		args = append(args, "--prune")
	}

	if err := Run(args, proxy, gitdir, timeout, stdout, nil); err != nil {
		return xerrors.Errorf("git clone failure: %w", err)
	}

	return nil
}

func WorkingRemote(gitdir string, timeout time.Duration) (remote string, err error) {
	stdout := &bytes.Buffer{}

	if err := Remote("", false, gitdir, "", timeout, stdout); err != nil {
		return "", xerrors.Errorf("git working remote failure: %w", err)
	}

	// origin  http://github.com:80/golang/dl.git (fetch)
	// r'^.*\s+(.*?)\s+.*$'
	//match := versionRE.FindStringSubmatch(stdout.String())
	match := remoteRE.FindStringSubmatch(stdout.String())

	if len(match) <= 0 {
		return "", xerrors.Errorf("git working remote failure: %w", errors.New("remote not found"))
	}

	remote = match[1]

	return remote, nil
}

func RevParse(workingDir string, timeOut time.Duration, args ...string) (stdout string, err error) {
	stdoutBuf := &bytes.Buffer{}

	gargs := []string{"rev-parse"}
	gargs = append(gargs, args...)

	if err = Run(gargs, "", workingDir, timeOut, stdoutBuf, nil); err != nil {
		return stdoutBuf.String(), xerrors.Errorf("git rev-parse failure: %w", err)
	}

	return stdoutBuf.String(), nil
}

func ResolveGitDir(workingDir string, timeOut time.Duration) (gitDir string, err error) {

	if gitDir, err = RevParse("", timeOut, "--resolve-git-dir", workingDir); err != nil {
		return gitDir, xerrors.Errorf("git rev-parse resolve-git-dir failure: %w", err)
	}

	if !filepath.IsAbs(gitDir) {
		if gitDir, err = filepath.Abs(gitDir); err != nil {
			return "", xerrors.Errorf("abs filepath failure: %w", err)
		}
	}

	return gitDir, nil
}

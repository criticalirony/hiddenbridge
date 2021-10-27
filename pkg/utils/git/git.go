package git

import (
	"context"
	"errors"
	"fmt"
	"hiddenbridge/pkg/utils"
	"hiddenbridge/pkg/utils/command"
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := command.Run(ctx, "", nil, gitBin, "version")
	if err != nil {
		log.Panic().Err(err).Msg("failed to get git executable version")
	}

	match := versionRE.FindStringSubmatch(string(out))
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

func Run(proxy, workingdir string, timeout time.Duration, args ...interface{}) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmdArgs := []string{"-c", "http.sslVerify=false"}
	if proxy != "" {
		cmdArgs = append(cmdArgs, "-c", fmt.Sprintf("http.proxy=%s", proxy))
	}

	var (
		out []byte
		err error
	)

	stringArgs := utils.StringList(args...)

	if out, err = command.Run(ctx, workingdir, nil, gitBin, cmdArgs, stringArgs); err != nil {
		return nil, xerrors.Errorf("failed to run git command: %w", err)
	}

	return out, nil
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

	if _, err := Run(proxy, "", timeout, args); err != nil {
		return xerrors.Errorf("git clone failure: %w", err)
	}

	return nil
}

func Init(repoDir string, isBare bool, timeout time.Duration) error {
	args := []string{"init"}

	if isBare {
		args = append(args, "--bare")
	}

	if _, err := Run("", "", timeout, args, repoDir); err != nil {
		return xerrors.Errorf("git init failure: %w", err)
	}

	return nil
}

func Remote(subcommand string, isPrune bool, gitdir string, proxy string, timeout time.Duration) ([]byte, error) {
	args := []string{"remote", "-v"}

	if subcommand != "" {
		args = append(args, subcommand)
	}

	if subcommand == "update" && isPrune {
		args = append(args, "--prune")
	}

	var (
		err error
		out []byte
	)

	if out, err = Run(proxy, gitdir, timeout, args); err != nil {
		return nil, xerrors.Errorf("git clone failure: %w", err)
	}

	return out, nil
}

func WorkingRemote(gitdir string, timeout time.Duration) (remote string, err error) {
	var (
		out []byte
	)

	if out, err = Remote("", false, gitdir, "", timeout); err != nil {
		return "", xerrors.Errorf("git working remote failure: %w", err)
	}

	// origin  http://github.com:80/golang/dl.git (fetch)
	// r'^.*\s+(.*?)\s+.*$'
	//match := versionRE.FindStringSubmatch(stdout.String())
	match := remoteRE.FindStringSubmatch(string(out))

	if len(match) <= 0 {
		return "", xerrors.Errorf("git working remote failure: %w", errors.New("remote not found"))
	}

	remote = match[1]

	return remote, nil
}

func RevParse(workingDir string, timeOut time.Duration, args ...string) (stdout string, err error) {
	var out []byte

	if out, err = Run("", workingDir, timeOut, "rev-parse", args); err != nil {
		return string(out), xerrors.Errorf("git rev-parse failure: %w", err)
	}

	return string(out), nil
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

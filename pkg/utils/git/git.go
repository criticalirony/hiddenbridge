package git

import (
	"hiddenbridge/pkg/utils/command"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/mod/semver"
)

const (
	minGitVer = "v1.8.3"
)

type Git struct {
	WorkingDir string
}

var (
	gitBin string

	versionRE = regexp.MustCompile(`(?s)^[^\d]*(\d+(?:\.\d+){0,2}).*$`)
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
	stdout := strings.Builder{}

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

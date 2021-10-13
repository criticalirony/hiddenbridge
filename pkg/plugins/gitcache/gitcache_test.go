package gitcache

import (
	"fmt"
	"hiddenbridge/pkg/options"
	"hiddenbridge/pkg/plugins"
	"hiddenbridge/pkg/utils"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

var (
	self       plugins.Plugin
	pluginName = utils.PackageAsName()

	host      = "testhost.org"
	cachePath = "/tmp/gitcache/test"

	opts = &options.OptionValue{}
)

func init() {
	SetupLogging("debug")

	self = plugins.PluginBuilder[pluginName]()

	opts.Set("hosts", []string{host})
	opts.Set("cache.path", cachePath)

	if err := os.RemoveAll(cachePath); err != nil {
		log.Panic().Msgf("faillure to remove: %s", cachePath)
	}

	if err := self.Init(opts); err != nil {
		log.Panic().Msgf("init failure: %+v", err)
	}
}

func SetupLogging(level string) {
	logLevel, err := zerolog.ParseLevel(level)
	if err != nil {
		log.Panic().Err(err).Msgf("Failed to parse log level: %s", level)
	}

	noColor := !utils.IsTerminal()
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, NoColor: noColor}).Level(logLevel).With().Timestamp().Logger().With().Caller().Logger()
}

func TestGitCacheSimple(t *testing.T) {
	var (
		err  error
		req  *http.Request
		resp *httptest.ResponseRecorder
	)

	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/sample/project.git/info/refs?service=git-upload-pack", host), nil)
	resp = httptest.NewRecorder()

	err = self.HandleResponse(resp, req, nil, http.StatusOK)
	require.Nil(t, err)

	res := resp.Result()
	require.NotEqual(t, http.StatusNotFound, res.StatusCode)
}

func TestGitCacheMethodHead(t *testing.T) {
	var (
		err  error
		req  *http.Request
		resp *httptest.ResponseRecorder
	)

	// Requesting HEAD
	req = httptest.NewRequest(http.MethodHead, fmt.Sprintf("http://%s/sample/project.git/info/refs?service=git-upload-pack", host), nil)
	resp = httptest.NewRecorder()

	err = self.HandleResponse(resp, req, nil, http.StatusOK)
	require.Nil(t, err)

	res := resp.Result()

	// Checking method has been updated to GET
	require.Equal(t, http.MethodGet, req.Method)
	require.NotEqual(t, http.StatusNotFound, res.StatusCode)
}

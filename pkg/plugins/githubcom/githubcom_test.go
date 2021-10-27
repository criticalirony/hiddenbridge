package githubcom

import (
	"context"
	"hiddenbridge/pkg/options"
	"hiddenbridge/pkg/plugins"
	"hiddenbridge/pkg/server/request"
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
	pluginName = utils.PackageAsName()
	self       plugins.Plugin

	host = "github.com"

	opts = &options.OptionValue{}
)

func init() {
	SetupLogging("debug")

	self = plugins.PluginBuilder[pluginName]()

	opts.Set("hosts", []string{host})
	opts.Set("cache.host", "gitcache.org")

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

func TestHandleRequestChainPlugin(t *testing.T) {
	uri := "https://github.com/golang/dl.git/info/refs?service=git-upload-pack"

	reqCtx := request.RequestContext{}
	req := httptest.NewRequest(http.MethodGet, uri, nil)
	req = req.WithContext(context.WithValue(req.Context(), request.ReqContextKey, reqCtx))

	resultURL, resultReq, err := self.HandleRequest(req.URL, req)
	require.Nil(t, err)
	require.Nil(t, resultReq)
	require.NotNil(t, resultURL)

	var chainPlugin string
	ok := utils.As(reqCtx["chain"], &chainPlugin)
	require.True(t, ok)
	require.Equal(t, "gitcache.org", chainPlugin)
}

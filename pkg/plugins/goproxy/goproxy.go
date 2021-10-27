package goproxy

import (
	"hiddenbridge/pkg/options"
	"hiddenbridge/pkg/plugins"
	"hiddenbridge/pkg/server/request"
	"hiddenbridge/pkg/utils"
	"io"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"golang.org/x/xerrors"
)

type GoProxyHandler struct {
	plugins.BasePlugin
	router *mux.Router
}

func init() {
	pluginName := utils.PackageAsName()
	if len(pluginName) == 0 {
		log.Panic().Msgf("failed to retrieve plugin name")
	}

	plugins.PluginBuilder[pluginName] = func() plugins.Plugin {
		h := GoProxyHandler{}
		h.Name_ = pluginName
		h.router = mux.NewRouter()
		return &h
	}
}

func (p *GoProxyHandler) Init(opts *options.OptionValue) error {
	if err := p.BasePlugin.Init(opts); err != nil {
		return xerrors.Errorf("plugin: %s failed to initialize base: %w", p.Name(), err)
	}
	p.router.StrictSlash(true)
	// p.router.HandleFunc("/certs/", p.HandleCertsReq)

	return nil
}

func (p *GoProxyHandler) HandleResponse(w http.ResponseWriter, req *http.Request, reqCtx request.RequestContext, body io.Reader, statusCode int) error {
	p.router.ServeHTTP(w, req)
	return nil // by default plugins will not change the response
}

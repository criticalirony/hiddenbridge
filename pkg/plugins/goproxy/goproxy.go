package goproxy

import (
	"hiddenbridge/pkg/options"
	"hiddenbridge/pkg/plugins"
	"hiddenbridge/pkg/utils"
	"io"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
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
	p.BasePlugin.Init(opts)
	p.router.StrictSlash(true)
	// p.router.HandleFunc("/certs/", p.HandleCertsReq)

	return nil
}

func (p *GoProxyHandler) HandleResponse(rw http.ResponseWriter, req *http.Request, body io.ReadCloser, statusCode int) error {
	p.router.ServeHTTP(rw, req)
	return nil // by default plugins will not change the response
}

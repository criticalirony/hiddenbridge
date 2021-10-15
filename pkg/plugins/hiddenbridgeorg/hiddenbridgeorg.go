package hiddenbridgeorg

import (
	"hiddenbridge/pkg/options"
	"hiddenbridge/pkg/plugins"
	"hiddenbridge/pkg/utils"
	"io"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"golang.org/x/xerrors"
)

type HiddenBridgeHandler struct {
	plugins.BasePlugin
	router *mux.Router
	cert   []byte
}

func init() {
	pluginName := utils.PackageAsName()
	if len(pluginName) == 0 {
		log.Panic().Msgf("failed to retrieve plugin name")
	}

	plugins.PluginBuilder[pluginName] = func() plugins.Plugin {
		h := HiddenBridgeHandler{}
		h.Name_ = pluginName
		h.router = mux.NewRouter()
		return &h
	}
}

func (p *HiddenBridgeHandler) Init(opts *options.OptionValue) error {
	if err := p.BasePlugin.Init(opts); err != nil {
		return xerrors.Errorf("plugin: %s failed to initialize base: %w", p.Name(), err)
	}
	p.router.StrictSlash(true)
	p.router.HandleFunc("/certs/", p.HandleCertsReq)

	return nil
}

func (p *HiddenBridgeHandler) HandleCertsReq(rw http.ResponseWriter, r *http.Request) {
	if p.cert == nil {
		certPath := p.Opts.GetDefault("ca.cert", "").String()
		if len(certPath) == 0 {
			http.Error(rw, xerrors.Errorf("%s plugin unable to locate certificate file", p.Name()).Error(), http.StatusInternalServerError)
			return
		}

		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			http.Error(rw, xerrors.Errorf("%s plugin unable to locate certificate file", p.Name()).Error(), http.StatusInternalServerError)
			return
		}

		var (
			err  error
			cert []byte
		)
		if cert, err = ioutil.ReadFile(certPath); err != nil {
			http.Error(rw, xerrors.Errorf("%s plugin unable to read certificate file", p.Name()).Error(), http.StatusInternalServerError)
			return
		}

		p.cert = cert
	}

	rw.Write(p.cert)
}

func (p *HiddenBridgeHandler) HandleResponse(w http.ResponseWriter, r *http.Request, body io.Reader, statusCode int) error {

	p.router.ServeHTTP(w, r)

	return nil // by default plugins will not change the response
}

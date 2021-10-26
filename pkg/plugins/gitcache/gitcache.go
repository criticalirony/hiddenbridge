package gitcache

import (
	"fmt"
	"hiddenbridge/pkg/options"
	"hiddenbridge/pkg/plugins"
	"hiddenbridge/pkg/server"
	"hiddenbridge/pkg/utils"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"golang.org/x/xerrors"
)

type GitCacheHandler struct {
	plugins.BasePlugin
	cachePath    string
	forwardProxy string
	r            *mux.Router
	hosts        map[string]struct{}
}

func init() {
	pluginName := utils.PackageAsName()
	if len(pluginName) == 0 {
		log.Panic().Msgf("failed to retrieve plugin name")
	}

	plugins.PluginBuilder[pluginName] = func() plugins.Plugin {
		h := GitCacheHandler{
			hosts: map[string]struct{}{},
		}
		h.Name_ = pluginName
		return &h
	}
}

func (p *GitCacheHandler) Init(opts *options.OptionValue) error {
	if err := p.BasePlugin.Init(opts); err != nil {
		return err
	}

	cachePath := opts.GetDefault("cache.path", "").String()
	if cachePath == "" {
		return xerrors.Errorf("cache.path config option not found")
	}

	if err := os.MkdirAll(cachePath, os.ModePerm); err != nil {
		return xerrors.Errorf("os.mkdirall failure: %w", err)
	}

	p.cachePath = cachePath
	p.r = mux.NewRouter()

	for _, item := range gitServices {
		p.r.HandleFunc(fmt.Sprintf(`/{path:.*?}%s`, item.Path), item.Handler).Methods(item.Method)
	}

	p.forwardProxy = p.Opts.GetDefault("forward.proxy", "").String()

	// Record the set of hosts that this plugin responds to.
	// This is used because it is possible that we will be called in a chain and will be given another host in the req
	for _, host := range p.Opts.GetDefault("hosts", nil).StringList() {
		p.hosts[host] = struct{}{}
	}

	return nil
}

func (p *GitCacheHandler) HandleRequest(reqURL *url.URL, req *http.Request) (*url.URL, *http.Request, error) {
	log.Debug().Msgf("%s handling request: %s", p.Name(), reqURL.String())

	if req.Method == http.MethodHead {
		req.Method = http.MethodGet
	}

	// Find a matching route for our request
	var match mux.RouteMatch
	var hasRoute bool = p.r.Match(req, &match)

	reqCtx := req.Context().Value(server.ReqContextKey).(server.RequestContext)

	// Pass context data between this request handler and our respective response handler
	reqCtx["reporoot"] = p.cachePath
	reqCtx["gitproxy"] = p.forwardProxy
	reqCtx["upstream"] = reqURL

	if hasRoute {
		req = mux.SetURLVars(req, match.Vars)
		match.Handler.ServeHTTP(nil, req) // Handle the request, but you can't send anything as a response, ResponseHandler will do that

		var err error
		if utils.As(reqCtx["err"], &err) && err != nil {
			return nil, nil, xerrors.Errorf("route handler failure: %w", err)
		}

		// The route handler may have updated the upstream reqURL so set it to its new value here
		if !utils.As(reqCtx["upstream"], &reqURL) {
			return nil, nil, xerrors.Errorf("update request URL failure")
		}
	}

	if !utils.URLIsEmpty(reqURL) {
		if _, ok := p.hosts[reqURL.Hostname()]; ok {
			reqURL = nil // This is a local request so we do not need to send the request further upstream
		}
	}

	return reqURL, req, nil

}

func (p *GitCacheHandler) HandleResponse(w http.ResponseWriter, req *http.Request, body io.Reader, statusCode int) error {
	log.Debug().Msgf("%s handling response: req: %s", p.Name(), req.URL.String())

	// Find a matching route for our request
	var match mux.RouteMatch
	var hasRoute bool = p.r.Match(req, &match)

	if hasRoute {
		var (
			reqCtx server.RequestContext
			ok     bool
		)

		if reqCtx, ok = req.Context().Value(server.ReqContextKey).(server.RequestContext); !ok {
			http.Error(w, fmt.Sprintf("unable to retrieve git cache context for this request: %s", req.URL.String()), http.StatusInternalServerError)
			return xerrors.Errorf("unable to retrieve git cache context for this request: %s", req.URL.String())
		}

		match.Handler.ServeHTTP(w, req) // Handle the response
		var err error
		utils.As(reqCtx["err"], &err)
		return err
	}

	return nil
}

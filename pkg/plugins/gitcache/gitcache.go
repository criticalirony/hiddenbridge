package gitcache

import (
	"context"
	"fmt"
	"hiddenbridge/pkg/options"
	"hiddenbridge/pkg/plugins"
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
}

func init() {
	pluginName := utils.PackageAsName()
	if len(pluginName) == 0 {
		log.Panic().Msgf("failed to retrieve plugin name")
	}

	plugins.PluginBuilder[pluginName] = func() plugins.Plugin {
		h := GitCacheHandler{}
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

	return nil
}

func (p *GitCacheHandler) HandleRequest(reqURL *url.URL, req *http.Request) (*url.URL, *http.Request, error) {
	//

	log.Debug().Msgf("%s handling request: %s", p.Name(), reqURL.String())
	// Find a matching route for our request
	var match mux.RouteMatch
	var hasRoute bool = p.r.Match(req, &match)

	// Fetch and decode the upstream url
	upstreamURL, err := utils.NormalizeURL(req.Header.Get("hb-git-upstream"))
	if err != nil {
		return nil, req, err
	}

	// Pass context between this request handler and our respective response handler
	gitRequestContext := &GitRequestContext{
		repoRoot: p.cachePath,
		gitProxy: p.forwardProxy,
	}

	// Shallow copy, not pointer assignment
	gitRequestContext.upstream = &url.URL{}
	if upstreamURL != nil {
		*gitRequestContext.upstream = *upstreamURL
	}

	req = req.WithContext(context.WithValue(req.Context(), reqContextKey, gitRequestContext))

	if hasRoute {
		req = mux.SetURLVars(req, match.Vars)
		match.Handler.ServeHTTP(nil, req) // Handle the request, but you can't send anything as a response, ResponseHandler will do that

		if gitRequestContext.upstream == nil {
			upstreamURL = nil
		}
	}

	return upstreamURL, req, gitRequestContext.err

}

func (p *GitCacheHandler) HandleResponse(w http.ResponseWriter, req *http.Request, body io.Reader, statusCode int) error {
	log.Debug().Msgf("%s handling response: req: %s", p.Name(), req.URL.String())

	// Find a matching route for our request
	var match mux.RouteMatch
	var hasRoute bool = p.r.Match(req, &match)

	// Fetch and decode the upstream url
	upstreamURL, err := utils.NormalizeURL(req.Header.Get("hb-git-upstream"))
	if err != nil {
		return err
	}

	if !hasRoute && utils.URLIsEmpty(upstreamURL) {
		http.NotFound(w, req)
		return nil
	}

	if hasRoute {
		var (
			reqCtx *GitRequestContext
			ok     bool
		)

		if reqCtx, ok = req.Context().Value(reqContextKey).(*GitRequestContext); !ok {
			http.Error(w, fmt.Sprintf("unable to retrieve git cache context for this request: %s", req.URL.String()), http.StatusInternalServerError)
			return xerrors.Errorf("unable to retrieve git cache context for this request: %s", req.URL.String())
		}

		// Update the request context with the response body and status code
		reqCtx.body = body
		reqCtx.statusCode = statusCode

		req = mux.SetURLVars(req, match.Vars)
		match.Handler.ServeHTTP(w, req) // Handle the request, but you can't send anything as a response, ResponseHandler will do that
	}

	return nil
}

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
	cachePath string

	r *mux.Router
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
		return xerrors.Errorf("plugin: %s failed to initialize base: %w", p.Name(), err)
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

	return nil
}

func (p *GitCacheHandler) HandleRequest(reqURL *url.URL, req *http.Request) (*url.URL, *http.Request, error) {
	log.Debug().Msgf("%s handling request: %s", p.Name(), reqURL.String())
	var (
		err          error
		upstreamHost string
		upstreamURL  *url.URL
	)

	urlQuery := reqURL.Query()

	// Find a matching route for our request
	var match mux.RouteMatch
	var hasRoute bool = p.r.Match(req, &match)

	// We have a route, also might have an upstream
	gitCacheContext := &GitRequestContext{
		repoRoot: p.cachePath,
	}

	req = req.WithContext(context.WithValue(req.Context(), gitCacheKey, gitCacheContext))

	if urlQuery.Has("upstream") {
		if upstreamHost, err = url.QueryUnescape(urlQuery.Get("upstream")); err != nil {
			return nil, nil, xerrors.Errorf("failled to unescape upstream host: %s: %w", urlQuery.Get("upstream"), err)
		}

		if upstreamURL, err = url.Parse(upstreamHost); err != nil {
			return nil, nil, xerrors.Errorf("failled to parse url of upstream host: %s: %w", urlQuery.Get("upstream"), err)
		}

		gitCacheContext.upstream = upstreamURL

		if !hasRoute {
			// We don't support the path locally, so hopefully the upstream server does
			// we might cache the path in the response
			gitCacheContext.status = http.StatusNotFound
			return upstreamURL, req, nil
		}
	}

	if !hasRoute {
		// Don't have a route and don't have an upstream, so just generate a 404 in the response
		gitCacheContext.status = http.StatusNotFound
		return nil, req, nil
	}

	req = mux.SetURLVars(req, match.Vars)
	match.Handler.ServeHTTP(nil, req) // Handle the request, but you can't send anything as a response, ResponseHandler will do that
	status := gitCacheContext.status

	if gitCacheContext.err != nil {
		gitCacheContext.status = http.StatusInternalServerError
		return nil, req, xerrors.Errorf("serve request route failure: %w", gitCacheContext.err)
	}

	if status == 0 {
		status = http.StatusOK
	}

	if status != http.StatusOK {
		// This request could not be served localy
		if upstreamURL != nil {
			// Get the upstream to serve the URL and possibly cache the response
			return upstreamURL, req, nil
		}

		// We couldn't serve the request locally and there's no upstream, so the response handler will return a 404
		return nil, req, nil // by default plugins will not round trip the request

	}

	// This request can be served locally regardless of upstream
	return nil, req, nil
}

func (p *GitCacheHandler) HandleResponse(w http.ResponseWriter, req *http.Request, body io.Reader, statusCode int) error {
	log.Debug().Msgf("%s handling response: req: %s", p.Name(), req.URL.String())

	if req.Method == http.MethodHead {
		req.Method = http.MethodGet
	}

	// p.r.ServeHTTP(w, r)
	return nil
}

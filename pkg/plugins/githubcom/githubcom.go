package githubcom

import (
	"fmt"
	"hiddenbridge/pkg/options"
	"hiddenbridge/pkg/plugins"
	"hiddenbridge/pkg/server/request"
	"hiddenbridge/pkg/utils"
	"io"
	"net/http"
	"net/url"

	"github.com/rs/zerolog/log"
	"golang.org/x/xerrors"
)

type GithubHandler struct {
	plugins.BasePlugin

	cacheHost string
}

func init() {
	pluginName := utils.PackageAsName()
	if len(pluginName) == 0 {
		log.Panic().Msgf("failed to retrieve plugin name")
	}

	plugins.PluginBuilder[pluginName] = func() plugins.Plugin {
		h := GithubHandler{}
		h.Name_ = pluginName
		return &h
	}
}

func (p *GithubHandler) Init(opts *options.OptionValue) error {
	if err := p.BasePlugin.Init(opts); err != nil {
		return err
	}

	p.cacheHost = opts.Get("cache.host").String()

	return nil
}

func (p *GithubHandler) RemoteURL(hostURL *url.URL) (*url.URL, error) {
	return nil, nil // We need this connection to be proxied
}

func (p *GithubHandler) HandleRequest(reqURL *url.URL, req **http.Request) (*url.URL, error) {
	log.Debug().Msgf("%s handling request: %s", p.Name(), reqURL.String())
	_req := *req

	reqCtx := _req.Context().Value(request.ReqContextKey).(request.RequestContext)
	if len(p.cacheHost) > 0 {
		// We have a caching host (plugin) so encode current request as a query param and pass onto the cacher
		reqCtx["chain"] = p.cacheHost
	}

	return reqURL, nil
}

func (p *GithubHandler) HandleResponse(w http.ResponseWriter, req *http.Request, reqCtx request.RequestContext, body io.Reader, statusCode int) error {
	log.Debug().Msgf("%s handling response: req: %s", p.Name(), req.URL.String())

	if statusCode >= http.StatusMovedPermanently && statusCode < http.StatusBadRequest {
		location := w.Header().Get("location")
		if len(location) == 0 {
			return nil
		}

		locationURL, err := utils.NormalizeURL(location)
		if err != nil {
			err = xerrors.Errorf("normalize url %s failure: %w", location, err)
			return err
		}

		var port string
		if locationURL.Scheme == "https" {
			p.Opts.GetDefault("ports.https[0]", "443").As(&port)
		} else {
			p.Opts.GetDefault("ports.http[0]", "80").As(&port)
		}

		locationURL.Host = fmt.Sprintf("%s:%s", locationURL.Hostname(), port)
		w.Header().Set("location", locationURL.String()) // Update redirected to a local listening port
	}

	return nil
}

func (p *GithubHandler) ProxyURL(hostURL *url.URL) (*url.URL, error) {
	proxy := p.Opts.GetDefault("host.real.proxy", "").String()
	if len(proxy) == 0 {
		return nil, nil
	}

	proxyURL, err := utils.NormalizeURL(proxy)
	if err != nil {
		err = xerrors.Errorf("normalize url %s failure: %w", proxyURL, err)
		return nil, err
	}

	return proxyURL, nil
}

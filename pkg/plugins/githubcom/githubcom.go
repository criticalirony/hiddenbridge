package githubcom

import (
	"fmt"
	"hiddenbridge/pkg/plugins"
	"hiddenbridge/pkg/server"
	"hiddenbridge/pkg/utils"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/rs/zerolog/log"
	"golang.org/x/xerrors"
)

type GithubHandler struct {
	plugins.BasePlugin
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

func (p *GithubHandler) RemoteURL(hostURL *url.URL) (*url.URL, error) {
	return nil, nil // We need this connection to be proxied
}

func (p *GithubHandler) findRepoNameIdx(path string) (offset, length int) {
	// var serviceIdx int
	repoPaths := []string{"info", "HEAD", "refs", "packed-refs", "objects", "branches", "hooks", "config", "description"}

	pathParts := strings.Split(path, "/")
	if len(pathParts) > 0 && pathParts[0] == "" {
		pathParts = pathParts[1:]
	}

	for i, pathPart := range pathParts {
		for _, repoPath := range repoPaths {
			if pathPart == repoPath {
				if i > 0 {
					repoName := pathParts[i-1]
					return strings.Index(path, repoName), len(repoName)
				}

				return -1, 0
			}
		}
	}

	return -1, 0
}

func (p *GithubHandler) HandleRequest(reqURL *url.URL, req *http.Request) (*url.URL, *http.Request, error) {
	log.Debug().Msgf("%s handling request: %s", p.Name(), reqURL.String())

	reqCtx := req.Context().Value(server.ReqContextKey).(server.RequestContext)

	cacheHost := p.Opts.Get("cache.host").String()
	if len(cacheHost) > 0 {
		// We have a caching host (plugin) so encode current request as a query param and pass onto the cacher
		reqCtx["chained"] = p.Opts.Get("cache.host").String()
	}

	return reqURL, nil, nil
}

func (p *GithubHandler) HandleResponse(w http.ResponseWriter, req *http.Request, body io.Reader, statusCode int) error {
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
			port = p.Opts.GetDefault("ports.https", "443").List()[0].String()
		} else {
			port = p.Opts.GetDefault("ports.http", "80").List()[0].String()
		}

		if len(port) == 0 {
			port = locationURL.Port()
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

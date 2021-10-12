package githubcom

import (
	"fmt"
	"hiddenbridge/pkg/plugins"
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

func (p *GithubHandler) HandleRequest(reqURL *url.URL, req *http.Request) (*url.URL, error) {
	var (
		upstream string
	)

	log.Debug().Msgf("orig request: %s", reqURL.String())

	upstream = p.Opts.Get("host.upstream").String()
	upstreamURL, err := utils.NormalizeURL(upstream)
	if err != nil {
		return nil, xerrors.Errorf("failed to normalize url %s: %w", upstream, err)
	}

	reqURL.Scheme = upstreamURL.Scheme
	reqURL.Host = upstreamURL.Host

	repoNameOff, repoNameLen := p.findRepoNameIdx(reqURL.Path)
	if repoNameOff >= 0 {
		repoName := reqURL.Path[repoNameOff : repoNameOff+repoNameLen]
		if !strings.HasPrefix(repoName, ".git") {
			repoName = repoName + ".git"
		}

		reqURL.Path = reqURL.Path[:repoNameOff] + repoName + reqURL.Path[repoNameOff+repoNameLen:]
	}

	reqURL.Path = upstreamURL.Path + reqURL.Path

	log.Debug().Msgf("new request: %s", reqURL.String())
	return reqURL, nil
}

func (p *GithubHandler) HandleResponse(rw http.ResponseWriter, req *http.Request, body io.ReadCloser, statusCode int) error {
	if statusCode >= http.StatusMovedPermanently && statusCode < http.StatusBadRequest {
		location := rw.Header().Get("location")
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
		rw.Header().Set("location", locationURL.String()) // Update redirected to a local listening port
	}

	// data := make([]byte, 10)
	// _, err := body.Read(data)
	// data, err := ioutil.ReadAll(body)
	// if err != nil {
	// 	return xerrors.Errorf("failure to read response body: %w", err)
	// }
	// defer body.Close()

	// log.Debug().Msgf("%v", rw.Header())
	// log.Debug().Msgf(string(data))

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

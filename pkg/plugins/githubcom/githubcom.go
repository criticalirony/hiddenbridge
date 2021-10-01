package githubcom

import (
	"fmt"
	"hiddenbridge/pkg/plugins"
	"hiddenbridge/pkg/utils"
	"io"
	"net/http"
	"net/url"

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

func (p *GithubHandler) HandleRequest(reqURL *url.URL, req *http.Request) (*url.URL, error) {

	var (
		realHost string
	)

	if reqURL.Scheme == "https" {
		realHost = p.Opts.Get("host.real.https").String()
	} else {
		realHost = p.Opts.Get("host.real.http").String()
	}

	if len(realHost) == 0 {
		log.Warn().Msgf("%s plugin did not find real url config now using %s", p.Name(), reqURL.Host)
		return reqURL, nil
	}

	realURL, err := utils.NormalizeURL(realHost)
	if err != nil {
		err = xerrors.Errorf("normalize url %s failure: %w", realHost, err)
		return nil, err
	}

	return realURL, nil
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

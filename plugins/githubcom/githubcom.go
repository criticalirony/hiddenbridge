package githubcom

import (
	"fmt"
	"hiddenbridge/plugins"
	"hiddenbridge/utils"
	"net/http"
	"net/url"

	"github.com/rs/zerolog/log"
	"golang.org/x/xerrors"
)

const (
	pluginName = "githubcom"
)

type GithubHandler struct {
	plugins.BasePlugin
}

func init() {
	plugins.PluginBuilder[pluginName] = func() plugins.Plugin {
		u := GithubHandler{}
		u.Name_ = pluginName
		return &u
	}
}

func (p *GithubHandler) HandlesURL(hostURL *url.URL) bool {

	secure := false
	if hostURL.Scheme == "https" {
		secure = true
	}

	hostPort := hostURL.Port()
	ports := p.Ports(secure)

	for _, availablePort := range ports {
		if hostPort == availablePort {
			return true
		}
	}

	var realHost string

	if secure {
		realHost = p.Opts_.Get("host.real.https", "").String()
	} else {
		realHost = p.Opts_.Get("host.real.http", "").String()
	}

	if len(realHost) != 0 {
		realURL, err := utils.NormalizeURL(realHost)
		if err != nil {
			log.Error().Err(err).Msgf("normalize url %s failure", realHost)
			return false
		}

		if realURL.Host == hostURL.Host {
			return true
		}
	}

	log.Warn().Msgf("plugin %s does not support %s", pluginName, hostURL)
	return false
}

func (p *GithubHandler) DirectRemote(hostURL *url.URL) (*url.URL, error) {
	return nil, nil // We need this connection to be proxied
}

func (p *GithubHandler) HandleRequest(reqURL *url.URL, req *http.Request) (*url.URL, error) {

	var (
		realHost string
	)

	if reqURL.Scheme == "https" {
		realHost = p.Opts_.Get("host.real.https", "").String()
	} else {
		realHost = p.Opts_.Get("host.real.http", "").String()
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

func (p *GithubHandler) HandleResponse(reqURL *url.URL, resp *http.Response) error {
	if resp.StatusCode >= http.StatusMovedPermanently && resp.StatusCode < http.StatusBadRequest {
		location := resp.Header.Get("location")
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
			port = p.Opts_.GetAsList("ports.https", []string{""})[0].String()
		} else {
			port = p.Opts_.GetAsList("ports.http", []string{""})[0].String()
		}

		if len(port) == 0 {
			port = locationURL.Port()
		}

		locationURL.Host = fmt.Sprintf("%s:%s", locationURL.Hostname(), port)
		resp.Header.Set("location", locationURL.String()) // Update redirected to a local listening port
	}

	return nil
}

func (p *GithubHandler) ProxyURL(hostURL *url.URL) (*url.URL, error) {
	proxy := p.Opts_.Get("host.real.proxy", "").String()
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

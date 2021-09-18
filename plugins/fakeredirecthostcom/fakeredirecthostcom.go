package fakeredirecthost

import (
	"fmt"
	"hiddenbridge/options"
	"hiddenbridge/plugins"
	"net/http"
	"net/url"

	"github.com/rs/zerolog/log"
)

const (
	pluginName = "fakeredirecthostcom"
)

type FakeRedirectHostHandler struct {
	plugins.BasePlugin
}

func init() {
	plugins.PluginBuilder[pluginName] = func() plugins.Plugin {
		u := FakeRedirectHostHandler{}
		u.Name_ = pluginName
		return &u
	}
}

func (p *FakeRedirectHostHandler) Init(opts *options.Options) error {
	p.BasePlugin.Init(opts)
	return nil
}

func (p *FakeRedirectHostHandler) HandlesURL(hostURL *url.URL) bool {

	secure := false
	if hostURL.Scheme == "https" {
		secure = true
	}

	port := hostURL.Port()
	ports := p.Ports(secure)

	for _, availablePort := range ports {
		if port == availablePort {
			return true
		}
	}

	log.Warn().Msgf("plugin %s does not support url %s", pluginName, hostURL.String())
	return false
}

func (p *FakeRedirectHostHandler) DirectRemote(hostURL *url.URL) (*url.URL, error) {
	// This plugin doesn't support direct connections
	return nil, nil
}

func (p *FakeRedirectHostHandler) ProxyURL(hostURL *url.URL) (*url.URL, error) {
	// This plugin doesn't require a proxy
	return nil, nil
}

func (p *FakeRedirectHostHandler) HandleRequest(reqURL *url.URL, req *http.Request) (*url.URL, *http.Request, error) {

	nextURL := *reqURL
	nextURL.Host = fmt.Sprintf("%s:%s", "fakehost.com", reqURL.Port())

	return &nextURL, req, nil // by default plugins will not round trip the request
}

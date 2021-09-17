package fakeredirecthost

import (
	"hiddenbridge/options"
	"hiddenbridge/plugins"
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

func (p *FakeRedirectHostHandler) Handles(hostURL *url.URL) bool {

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

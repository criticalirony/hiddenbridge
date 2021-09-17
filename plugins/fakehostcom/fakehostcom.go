package fakehostcom

import (
	"hiddenbridge/options"
	"hiddenbridge/plugins"
	"hiddenbridge/utils"
	"net/url"

	"github.com/rs/zerolog/log"
	"golang.org/x/xerrors"
)

const (
	pluginName = "fakehostcom"
)

type FakeHostHandler struct {
	plugins.BasePlugin
}

func init() {
	plugins.PluginBuilder[pluginName] = func() plugins.Plugin {
		u := FakeHostHandler{}
		u.Name_ = pluginName
		return &u
	}
}

func (p *FakeHostHandler) Init(opts *options.Options) error {
	p.BasePlugin.Init(opts)
	return nil
}

func (p *FakeHostHandler) Handles(hostURL *url.URL) bool {

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

	log.Warn().Msgf("plugin %s does not support %s", pluginName, hostURL)
	return false
}

func (p *FakeHostHandler) DirectRemote(hostURL *url.URL) (*url.URL, error) {
	var (
		realHost string
	)

	secure := false
	if hostURL.Scheme == "https" {
		secure = true
	}

	if secure {
		realHost = p.Opts_.Get("host.real.secure", hostURL.String()).String()
	} else {
		realHost = p.Opts_.Get("host.real.insecure", hostURL.String()).String()
	}

	realURL, err := utils.NormalizeURL(realHost)
	if err != nil {
		err = xerrors.Errorf("normalize url %s failure: %w", realURL)
		return nil, err
	}

	return realURL, nil
}

func (p *FakeHostHandler) ProxyURL(hostURL *url.URL) (*url.URL, error) {
	return utils.NormalizeURL(p.Opts_.Get("host.real.proxy", "").String())
}

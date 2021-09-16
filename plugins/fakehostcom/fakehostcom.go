package githubcom

import (
	"hiddenbridge/options"
	"hiddenbridge/plugins"
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

func (p *FakeHostHandler) Handles(host string, port int, secure bool) bool {

	ports := p.Ports(secure)

	for _, availablePort := range ports {
		if port == availablePort {
			return true
		}
	}

	return false
}

func (p *FakeHostHandler) DirectRemote(host string, port int, secure bool) (string, int) {
	var (
		realHost string
		realPort int
	)

	realHost = p.Opts_.Get("host.real", host).String()
	if secure {
		realPort = p.Opts_.Get("port.real.secure", port).Int()
	} else {
		realPort = p.Opts_.Get("port.real.insecure", port).Int()
	}

	return realHost, realPort // by default plugins will expect a direct (non intercepted) connection
}

func (p *FakeHostHandler) ProxyURL(host string, port int, secure bool) (string, error) {
	return p.Opts_.Get("host.real.proxy", "").String(), nil
}

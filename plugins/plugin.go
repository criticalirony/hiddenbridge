package plugins

import (
	"fmt"
	"hiddenbridge/options"
	"net/url"
)

var (
	// PluginBuilder is a map of plugin name to a (func() plugins.Plugin) that can create a Plugin
	PluginBuilder map[string]func() Plugin
)

// Plugin interface, defines a plugin
// All plugins must embed the BasePlugin, which also implements simple defaults for all functions
type Plugin interface {
	Name() string
	Init(opts *options.Options) error
	String() string
	Ports(bool) []string
	Handles(hostURL *url.URL) bool
	DirectRemote(hostURL *url.URL) (*url.URL, error)
	ProxyURL(hostURL *url.URL) (*url.URL, error)
}

func init() {
	PluginBuilder = map[string]func() Plugin{}
}

// BasePlugin - All services must embed the BasePlugin, which also implements simple defaults for all functions
type BasePlugin struct {
	Name_ string
	Opts_ *options.Options
}

func (b *BasePlugin) Name() string {
	return b.Name_
}

func (b *BasePlugin) Init(opts *options.Options) error {
	b.Opts_ = opts
	return nil
}

func (b *BasePlugin) String() string {
	return fmt.Sprintf("%s=", b.Name_)
}

func (b *BasePlugin) Ports(secure bool) []string {
	var portOpts []options.OptionValue

	if secure {
		portOpts = b.Opts_.GetAsList("ports.secure", nil)
	} else {
		portOpts = b.Opts_.GetAsList("ports.insecure", nil)
	}

	ports := make([]string, len(portOpts))
	for i, port := range portOpts {
		ports[i] = port.String()
	}

	return ports
}

func (b *BasePlugin) Handles(hostURL *url.URL) bool {
	return false // by default plugins don't handle anything - this gets overriden by the plugin
}

func (b *BasePlugin) DirectRemote(hostURL *url.URL) (*url.URL, error) {
	return hostURL, nil // by default plugins will expect a direct (non intercepted) connection
}

func (b *BasePlugin) ProxyURL(hostURL *url.URL) (*url.URL, error) {
	return nil, nil // by default plugins will not require a proxy for their requests
}

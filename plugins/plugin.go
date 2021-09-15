package plugins

import (
	"fmt"
	"hiddenbridge/options"
)

var (
	// PluginBuilder is a map of plugin name to a (func() plugins.Plugin) that can create a Plugin
	PluginBuilder map[string]func() Plugin
)

// Plugin interface, defines a plugin
// All plugins must embed the BasePlugin, which also implements simple defaults for all functions
type Plugin interface {
	Init(opts *options.Options) error
	String() string
	Ports(bool) []int
}

func init() {
	PluginBuilder = map[string]func() Plugin{}
}

// BasePlugin - All services must embed the BasePlugin, which also implements simple defaults for all functions
type BasePlugin struct {
	Name string
	Opts *options.Options
}

func (b *BasePlugin) Init(opts *options.Options) error {
	b.Opts = opts
	return nil
}

func (b *BasePlugin) String() string {
	return fmt.Sprintf("%s=", b.Name)
}

func (b *BasePlugin) Ports(secure bool) []int {
	var portOpts []options.OptionValue

	if secure {
		portOpts = b.Opts.GetAsList("ports.secure", nil)
	} else {
		portOpts = b.Opts.GetAsList("ports.insecure", nil)
	}

	ports := make([]int, len(portOpts))
	for i, port := range portOpts {
		ports[i] = port.Int()
	}

	return ports
}

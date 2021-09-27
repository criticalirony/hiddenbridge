package goproxy

import (
	"hiddenbridge/plugins"
)

const (
	pluginName = "goproxy"
)

type GoProxyHandler struct {
	plugins.BasePlugin
}

func init() {
	plugins.PluginBuilder[pluginName] = func() plugins.Plugin {
		u := GoProxyHandler{}
		u.Name_ = pluginName
		return &u
	}
}

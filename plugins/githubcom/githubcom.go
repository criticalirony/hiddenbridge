package githubcom

import (
	"hiddenbridge/options"
	"hiddenbridge/plugins"
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
		u.Name = pluginName
		return &u
	}
}

func (p *GithubHandler) Init(opts *options.Options) error {
	p.BasePlugin.Init(opts)
	return nil
}

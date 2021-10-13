package gitcache

import (
	"context"
	"fmt"
	"hiddenbridge/pkg/options"
	"hiddenbridge/pkg/plugins"
	"hiddenbridge/pkg/utils"
	"io"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"golang.org/x/xerrors"
)

type GitCacheHandler struct {
	plugins.BasePlugin
	cachePath string

	r *mux.Router
}

func init() {
	pluginName := utils.PackageAsName()
	if len(pluginName) == 0 {
		log.Panic().Msgf("failed to retrieve plugin name")
	}

	plugins.PluginBuilder[pluginName] = func() plugins.Plugin {
		h := GitCacheHandler{}
		h.Name_ = pluginName
		return &h
	}
}

func (p *GitCacheHandler) Init(opts *options.OptionValue) error {
	if err := p.BasePlugin.Init(opts); err != nil {
		return xerrors.Errorf("plugin: %s failed to initialize base: %w", p.Name(), err)
	}

	cachePath := opts.GetDefault("cache.path", "").String()
	if cachePath == "" {
		return xerrors.Errorf("cache.path config option not found")
	}

	if err := os.MkdirAll(cachePath, os.ModePerm); err != nil {
		return xerrors.Errorf("os.mkdirall failure: %w", err)
	}

	p.cachePath = cachePath
	p.r = mux.NewRouter()

	for _, item := range gitServices {
		p.r.HandleFunc(fmt.Sprintf(`/{path:.*?}%s`, item.Path), item.Handler).Methods(item.Method)
	}

	return nil
}

func (p *GitCacheHandler) HandleResponse(w http.ResponseWriter, r *http.Request, body io.ReadCloser, statusCode int) error {
	if r.Method == http.MethodHead {
		r.Method = http.MethodGet
	}

	r = r.WithContext(context.WithValue(r.Context(), gitRepoRootKey, p.cachePath))

	p.r.ServeHTTP(w, r)
	return nil
}

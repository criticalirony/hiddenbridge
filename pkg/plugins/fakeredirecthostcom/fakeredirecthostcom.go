package fakeredirecthost

import (
	"fmt"
	"hiddenbridge/pkg/options"
	"hiddenbridge/pkg/plugins"
	"hiddenbridge/pkg/utils"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/rs/zerolog/log"
	"golang.org/x/xerrors"
)

type FakeRedirectHostHandler struct {
	plugins.BasePlugin
}

func init() {
	pluginName := utils.PackageAsName()
	if len(pluginName) == 0 {
		log.Panic().Msgf("failed to retrieve plugin name")
	}
	plugins.PluginBuilder[pluginName] = func() plugins.Plugin {
		h := FakeRedirectHostHandler{}
		h.Name_ = pluginName
		return &h
	}
}

func (p *FakeRedirectHostHandler) Init(opts *options.OptionValue) error {
	if err := p.BasePlugin.Init(opts); err != nil {
		return xerrors.Errorf("plugin: %s failed to initialize base: %w", p.Name(), err)
	}
	return nil
}

func (p *FakeRedirectHostHandler) HandlesURL(hostURL *url.URL) bool {
	port := hostURL.Port()
	ports := p.Ports(hostURL.Scheme)

	for _, availablePort := range ports {
		if port == availablePort {
			return true
		}
	}

	log.Warn().Msgf("plugin %s does not support url %s", p.Name(), hostURL.String())
	return false
}

func (p *FakeRedirectHostHandler) RemoteURL(hostURL *url.URL) (*url.URL, error) {
	// This plugin doesn't support direct connections
	return nil, nil
}

func (p *FakeRedirectHostHandler) ProxyURL(hostURL *url.URL) (*url.URL, error) {
	// This plugin doesn't require a proxy
	return nil, nil
}

func (p *FakeRedirectHostHandler) HandleRequest(rURL *url.URL, r *http.Request) (*url.URL, error) {

	path := r.URL.Path
	if strings.Contains(path, "/custom") {
		return nil, nil
	}

	nextURL := *rURL
	nextURL.Host = fmt.Sprintf("%s:%s", "fakehost.com", rURL.Port())

	return &nextURL, nil
}

func (p *FakeRedirectHostHandler) HandleResponse(w http.ResponseWriter, r *http.Request, body io.ReadCloser, statusCode int) error {
	respBody := "<HTML><HEAD><TITLE>Custom response</TITLE></HEAD><BODY>This here be a custom response!</BODY></HTML>\r\n"

	if _, err := io.WriteString(w, respBody); err != nil {
		return xerrors.Errorf("failed to write response body for req %s: %w", r.URL.String(), err)
	}
	return nil
}

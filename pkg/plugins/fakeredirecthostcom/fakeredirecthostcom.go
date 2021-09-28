package fakeredirecthost

import (
	"bytes"
	"fmt"
	"hiddenbridge/options"
	"hiddenbridge/plugins"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

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

func (p *FakeRedirectHostHandler) RemoteURL(hostURL *url.URL) (*url.URL, error) {
	// This plugin doesn't support direct connections
	return nil, nil
}

func (p *FakeRedirectHostHandler) ProxyURL(hostURL *url.URL) (*url.URL, error) {
	// This plugin doesn't require a proxy
	return nil, nil
}

func (p *FakeRedirectHostHandler) HandleRequest(reqURL *url.URL, req *http.Request) (*url.URL, error) {

	path := req.URL.Path
	if strings.Contains(path, "/custom") {
		return nil, nil
	}

	nextURL := *reqURL
	nextURL.Host = fmt.Sprintf("%s:%s", "fakehost.com", reqURL.Port())

	return &nextURL, nil
}

func (p *FakeRedirectHostHandler) HandleResponse(reqURL *url.URL, resp *http.Response) error {
	body := "<HTML><HEAD><TITLE>Custom response</TITLE></HEAD><BODY>This here be a custom response!</BODY></HTML>\r\n"
	resp.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))
	return nil
}

package goproxy

import (
	"crypto/tls"
	"hiddenbridge/plugins"
	"net/http"
	"net/url"
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

func (b *GoProxyHandler) HandlesURL(hostURL *url.URL) bool {
	return false // by default plugins don't handle anything - this gets overriden by the plugin
}

func (b *GoProxyHandler) RemoteURL(hostURL *url.URL) (*url.URL, error) {
	return hostURL, nil // by default plugins will expect a direct (non intercepted) connection
}

func (b *GoProxyHandler) ProxyURL(hostURL *url.URL) (*url.URL, error) {
	return nil, nil // by default plugins will not require a proxy for their requests
}

func (b *GoProxyHandler) HandleCertificate(site string) (*tls.Certificate, error) {
	if cert, ok := b.Certs[site]; ok {
		return cert, nil // by default plugins will return a site certificate if they have one
	}

	return nil, nil // not finding a site certificate is considered not an error
}

func (b *GoProxyHandler) HandleRequest(reqURL *url.URL, req *http.Request) (*url.URL, error) {
	return nil, nil // by default plugins will not round trip the request
}

func (b *GoProxyHandler) HandleResponse(reqURL *url.URL, resp *http.Response) error {
	return nil // by default plugins will not change the response
}

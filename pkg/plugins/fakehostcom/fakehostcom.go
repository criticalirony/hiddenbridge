package fakehostcom

import (
	"bytes"
	"hiddenbridge/pkg/options"
	"hiddenbridge/pkg/plugins"
	"hiddenbridge/pkg/server/request"
	"hiddenbridge/pkg/utils"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/rs/zerolog/log"
	"golang.org/x/xerrors"
)

type FakeHostHandler struct {
	plugins.BasePlugin
}

func init() {
	pluginName := utils.PackageAsName()
	if len(pluginName) == 0 {
		log.Panic().Msgf("failed to retrieve plugin name")
	}

	plugins.PluginBuilder[pluginName] = func() plugins.Plugin {
		h := FakeHostHandler{}
		h.BasePlugin.Name_ = pluginName
		return &h
	}
}

func (p *FakeHostHandler) Init(opts *options.OptionValue) error {
	if err := p.BasePlugin.Init(opts); err != nil {
		return xerrors.Errorf("plugin: %s failed to initialize base: %w", p.Name(), err)
	}
	return nil
}

func (p *FakeHostHandler) HandlesURL(hostURL *url.URL) bool {
	hostPort := hostURL.Port()
	ports := p.Ports(hostURL.Scheme)

	for _, availablePort := range ports {
		if hostPort == availablePort {
			return true
		}
	}

	log.Warn().Msgf("plugin %s does not support %s", p.Name(), hostURL)
	return false
}

func (p *FakeHostHandler) ProxyURL(hostURL *url.URL) (*url.URL, error) {
	return utils.NormalizeURL(p.Opts.Get("host.real.proxy").String())
}

func (p *FakeHostHandler) RemoteURL(hostURL *url.URL) (*url.URL, error) {
	var (
		realHost string
	)

	if hostURL.Scheme == "https" {
		realHost = p.Opts.GetDefault("host.real.https", hostURL.String()).String()
	} else {
		realHost = p.Opts.GetDefault("host.real.http", hostURL.String()).String()
	}

	realURL, err := utils.NormalizeURL(realHost)
	if err != nil {
		err = xerrors.Errorf("normalize url %s failure: %w", realURL, err)
		return nil, err
	}

	return realURL, nil
}

func (p *FakeHostHandler) HandleRequest(reqURL *url.URL, req **http.Request) (*url.URL, error) {
	directURL, err := p.RemoteURL(reqURL)
	return directURL, err
}

func (p *FakeHostHandler) HandleResponse(w http.ResponseWriter, req *http.Request, reqCtx request.RequestContext, body io.Reader, statusCode int) error {
	// Test to check that we can change the body of a response
	var bodyBytes []byte
	var err error

	reqURL, err := utils.NormalizeURL(req.URL.String())
	if err != nil {
		return xerrors.Errorf("failed to normailze request url %s", req.URL.String())
	}

	if bodyBytes, err = ioutil.ReadAll(body); err != nil {
		return xerrors.Errorf("failed to read body of response from request %s: %w", reqURL.String(), err)
	}

	bodyBytes = bytes.Replace(bodyBytes, []byte("Served to you from a server far, far, away."), []byte("Served to you from a dish that's best served cold."), -1)
	if _, err = w.Write(bodyBytes); err != nil {
		return xerrors.Errorf("failed to write response body for request %s: %w", reqURL.String(), err)
	}

	return nil
}

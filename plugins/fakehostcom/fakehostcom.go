package fakehostcom

import (
	"bytes"
	"hiddenbridge/options"
	"hiddenbridge/plugins"
	"hiddenbridge/utils"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"

	"github.com/rs/zerolog/log"
	"golang.org/x/xerrors"
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

func (p *FakeHostHandler) HandlesURL(hostURL *url.URL) bool {

	secure := false
	if hostURL.Scheme == "https" {
		secure = true
	}

	hostPort := hostURL.Port()
	ports := p.Ports(secure)

	for _, availablePort := range ports {
		if hostPort == availablePort {
			return true
		}
	}

	log.Warn().Msgf("plugin %s does not support %s", pluginName, hostURL)
	return false
}

func (p *FakeHostHandler) ProxyURL(hostURL *url.URL) (*url.URL, error) {
	return utils.NormalizeURL(p.Opts_.Get("host.real.proxy", "").String())
}

func (p *FakeHostHandler) DirectRemote(hostURL *url.URL) (*url.URL, error) {
	var (
		realHost string
	)

	secure := false
	if hostURL.Scheme == "https" {
		secure = true
	}

	if secure {
		realHost = p.Opts_.Get("host.real.secure", hostURL.String()).String()
	} else {
		realHost = p.Opts_.Get("host.real.insecure", hostURL.String()).String()
	}

	realURL, err := utils.NormalizeURL(realHost)
	if err != nil {
		err = xerrors.Errorf("normalize url %s failure: %w", realURL, err)
		return nil, err
	}

	return realURL, nil
}

func (p *FakeHostHandler) HandleRequest(reqURL *url.URL, req *http.Request) (*url.URL, error) {
	directURL, err := p.DirectRemote(reqURL)
	return directURL, err
}

func (p *FakeHostHandler) HandleResponse(reqURL *url.URL, resp *http.Response) error {
	// Test to check that we can change the body of a response
	var bodyBytes []byte
	var err error

	bodyBytes, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	bodyBytes = bytes.Replace(bodyBytes, []byte("Served to you from a server far, far, away."), []byte("Served to you from a dish that's best served cold."), -1)
	resp.Header.Set("content-length", strconv.Itoa(len(bodyBytes)))

	//reset the response body to the original unread state
	resp.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	return err
}

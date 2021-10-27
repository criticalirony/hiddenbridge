package plugins

import (
	"crypto/tls"
	"fmt"
	"hiddenbridge/pkg/options"
	"hiddenbridge/pkg/server/request"
	"io"
	"net/http"
	"net/url"

	"golang.org/x/xerrors"
)

var (
	// PluginBuilder is a map of plugin name to a (func() plugins.Plugin) that can create a Plugin
	PluginBuilder map[string]func() Plugin
)

// Plugin interface, defines a plugin
// All plugins must embed the BasePlugin, which also implements simple defaults for all functions
type Plugin interface {
	Name() string
	Init(opts *options.OptionValue) error
	String() string
	Ports(string) []string
	HandlesURL(hostURL *url.URL) bool
	RemoteURL(hostURL *url.URL) (*url.URL, error)
	ProxyURL(hostURL *url.URL) (*url.URL, error)
	HandleCertificate(site string) (*tls.Certificate, error)
	HandleRequest(reqURL *url.URL, req *http.Request) (*url.URL, *http.Request, error)
	HandleResponse(w http.ResponseWriter, req *http.Request, reqCtx request.RequestContext, body io.Reader, statusCode int) error
}

func init() {
	PluginBuilder = map[string]func() Plugin{}
}

// BasePlugin - All services must embed the BasePlugin, which also implements simple defaults for all functions
type BasePlugin struct {
	Name_ string
	Opts  *options.OptionValue
	Hosts map[string]struct{}
	Certs map[string]*tls.Certificate
}

func (p *BasePlugin) Name() string {
	return p.Name_
}

func (p *BasePlugin) Init(opts *options.OptionValue) error {
	p.Opts = opts

	// Expected config if a plugin wants to host its own certificate
	certFiles := p.Opts.GetDefault("site.certs", nil).StringList()
	keyFiles := p.Opts.GetDefault("site.keys", nil).StringList()
	hosts := p.Opts.Get("hosts").StringList()

	if len(hosts) == 0 {
		return xerrors.Errorf("no configured hosts for plugin")
	}

	if p.Hosts == nil {
		p.Hosts = map[string]struct{}{}
	}

	// Record the set of hosts that this plugin responds to.
	// This is used because it is possible that we will be called in a chain and will be given another host in the req
	for _, host := range p.Opts.GetDefault("hosts", nil).StringList() {
		p.Hosts[host] = struct{}{}
	}

	if len(certFiles) != len(keyFiles) {
		return xerrors.Errorf("invalid 1:1 mapping of X509 key pairs and certs")
	}

	if len(certFiles) > 0 && len(certFiles) != len(hosts) {
		return xerrors.Errorf("invalid 1:1 mapping of hosts and and certs")
	}

	p.Certs = map[string]*tls.Certificate{}

	for i, certFile := range certFiles {
		// log.Debug().Msgf("Cert file: %s", certFile.String())
		// log.Debug().Msgf("Key file: %s", keyFiles[i].String())

		cert, err := tls.LoadX509KeyPair(certFile, keyFiles[i])
		if err != nil {
			return xerrors.Errorf("failed to load X509 key pair cert '%s' key '%s': %w", certFiles, keyFiles, err)
		}
		p.Certs[hosts[i]] = &cert
	}

	return nil
}

func (p *BasePlugin) String() string {
	return fmt.Sprintf("%s=", p.Name_)
}

func (p *BasePlugin) Ports(protocol string) []string {
	key := fmt.Sprintf("ports.%s", protocol)
	ports := p.Opts.Get(key).StringList()

	return ports
}

func (p *BasePlugin) HandleCertificate(site string) (*tls.Certificate, error) {
	if cert, ok := p.Certs[site]; ok {
		return cert, nil // by default plugins will return a site certificate if they have one
	}

	return nil, nil // not finding a site certificate is considered not an error
}

// Thes functions can be overriden in the plugin for custom behavior
func (p *BasePlugin) HandlesURL(hostURL *url.URL) bool {
	return true // by default plugins handle everything - this can be overriden by the plugin
}

func (p *BasePlugin) RemoteURL(hostURL *url.URL) (*url.URL, error) {
	// by default plugins will be expected to handle an intercepted connection
	// the base plugin can't support a direct, remote connection (nothing to connect to)
	return nil, nil
}

func (p *BasePlugin) ProxyURL(hostURL *url.URL) (*url.URL, error) {
	return nil, nil // by default plugins will not require a proxy for their requests
}

func (p *BasePlugin) HandleRequest(reqURL *url.URL, req *http.Request) (*url.URL, *http.Request, error) {
	return nil, nil, nil // by default plugins will not round trip the request
}

func (p *BasePlugin) HandleResponse(w http.ResponseWriter, r *http.Request, body io.Reader, statusCode int) error {
	return nil // by default plugins will not change the response
}

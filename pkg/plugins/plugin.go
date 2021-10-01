package plugins

import (
	"crypto/tls"
	"fmt"
	"hiddenbridge/pkg/options"
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
	HandleRequest(reqURL *url.URL, req *http.Request) (*url.URL, error)
	HandleResponse(rw http.ResponseWriter, req *http.Request, body io.ReadCloser, statusCode int) error
}

func init() {
	PluginBuilder = map[string]func() Plugin{}
}

// BasePlugin - All services must embed the BasePlugin, which also implements simple defaults for all functions
type BasePlugin struct {
	Name_ string
	Opts  *options.OptionValue
	Certs map[string]*tls.Certificate
}

func (b *BasePlugin) Name() string {
	return b.Name_
}

func (b *BasePlugin) Init(opts *options.OptionValue) error {
	b.Opts = opts

	// Expected config if a plugin wants to host its own certificate
	certFiles := b.Opts.GetDefault("site.certs", nil).List()
	keyFiles := b.Opts.GetDefault("site.keys", nil).List()
	hosts := b.Opts.Get("hosts").List()

	if len(certFiles) != len(keyFiles) {
		return xerrors.Errorf("invalid 1:1 mapping of X509 key pairs and certs")
	}

	if len(certFiles) > 0 && len(certFiles) != len(hosts) {
		return xerrors.Errorf("invalid 1:1 mapping of hosts and and certs")
	}

	b.Certs = map[string]*tls.Certificate{}

	for i, certFile := range certFiles {
		// log.Debug().Msgf("Cert file: %s", certFile.String())
		// log.Debug().Msgf("Key file: %s", keyFiles[i].String())

		cert, err := tls.LoadX509KeyPair(certFile.String(), keyFiles[i].String())
		if err != nil {
			return xerrors.Errorf("failed to load X509 key pair cert '%s' key '%s': %w", certFiles, keyFiles, err)
		}
		b.Certs[hosts[i].String()] = &cert
	}

	return nil
}

func (b *BasePlugin) String() string {
	return fmt.Sprintf("%s=", b.Name_)
}

func (b *BasePlugin) Ports(protocol string) []string {
	key := fmt.Sprintf("ports.%s", protocol)
	ports := b.Opts.Get(key).StringList()

	return ports
}

func (b *BasePlugin) HandleCertificate(site string) (*tls.Certificate, error) {
	if cert, ok := b.Certs[site]; ok {
		return cert, nil // by default plugins will return a site certificate if they have one
	}

	return nil, nil // not finding a site certificate is considered not an error
}

// Thes functions can be overriden in the plugin for custom behavior
func (b *BasePlugin) HandlesURL(hostURL *url.URL) bool {
	return true // by default plugins handle everything - this can be overriden by the plugin
}

func (b *BasePlugin) RemoteURL(hostURL *url.URL) (*url.URL, error) {
	// by default plugins will be expected to handle an intercepted connection
	// the base plugin can't support a direct, remote connection (nothing to connect to)
	return nil, nil
}

func (b *BasePlugin) ProxyURL(hostURL *url.URL) (*url.URL, error) {
	return nil, nil // by default plugins will not require a proxy for their requests
}

func (b *BasePlugin) HandleRequest(reqURL *url.URL, req *http.Request) (*url.URL, error) {
	return nil, nil // by default plugins will not round trip the request
}

func (b *BasePlugin) HandleResponse(rw http.ResponseWriter, reqURL *url.URL, body io.ReadCloser, statusCode int) error {
	return nil // by default plugins will not change the response
}

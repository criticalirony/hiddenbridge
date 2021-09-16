package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"hiddenbridge/options"
	"hiddenbridge/plugins"
	"hiddenbridge/utils"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"
)

var (
	ClosedChan chan struct{}
)

type ProxyServer struct {
	Name    string
	Opts    *options.Options
	Plugins map[string]plugins.Plugin
	Started chan struct{}
	Addr    string
	Ports   []int

	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	servers []*http.Server
}

func init() {
	ClosedChan = make(chan struct{})
	close(ClosedChan)
}

func NewProxyServer() *ProxyServer {
	return &ProxyServer{
		Name:    "hiddenbridge",
		Started: make(chan struct{}),
		wg:      sync.WaitGroup{},
		servers: []*http.Server{},
	}
}

func (s *ProxyServer) parseYamlConfig(yamConfigFile string) (serverConfig map[string]interface{}, pluginsConfig map[string]interface{}, err error) {

	var config map[string]map[string]interface{}
	var yamlFile []byte

	if yamlFile, err = ioutil.ReadFile(yamConfigFile); err != nil {
		err = xerrors.Errorf("failed to read config file %s %w", yamConfigFile, err)
		return
	}

	if err = yaml.Unmarshal(yamlFile, &config); err != nil {
		err = xerrors.Errorf("failed to unmarshal config %s %w", yamConfigFile, err)
		return
	}

	var ok bool

	if pluginsConfig, ok = config["proxy_plugins"]; !ok {
		pluginsConfig = map[string]interface{}{}
	}

	if serverConfig, ok = config["proxy_server"]; !ok {
		serverConfig = map[string]interface{}{}
	}

	return
}

func (s *ProxyServer) findPlugin(host string, port int, secure bool) plugins.Plugin {
	var (
		ok   bool
		plug plugins.Plugin
	)

	searchHost := host
	for len(searchHost) > 0 {
		plug, ok = s.Plugins[searchHost]
		if !ok {
			if idx := strings.Index(searchHost, "."); idx >= 0 {
				searchHost = searchHost[idx+1:]
			} else {
				searchHost = ""
			}
		} else {
			break
		}
	}

	if plug != nil && plug.Handles(host, port, secure) {
		return plug
	}

	return nil
}

func (s *ProxyServer) Init(configFile string) (err error) {
	var serverConfig map[string]interface{}
	var pluginsConfig map[string]interface{}

	if strings.HasSuffix(configFile, ".yml") || strings.HasSuffix(configFile, ".yaml") {
		if serverConfig, pluginsConfig, err = s.parseYamlConfig(configFile); err != nil {
			return
		}
	} else {
		err = xerrors.Errorf("unsupported config file %s", configFile)
		return
	}

	psvrOpts := options.FromMap("server", serverConfig)
	s.Opts = psvrOpts

	// Initialize plugins
	plugs := map[string]plugins.Plugin{}

	for name, plugNewFn := range plugins.PluginBuilder {
		pOPts := options.FromMap(name, pluginsConfig[name].(map[string]interface{}))
		plugin := plugNewFn()
		plugin.Init(pOPts)

		hosts := pOPts.GetAsList("hosts", nil)
		for _, host := range hosts {
			plugs[host.String()] = plugin
			log.Info().Msgf("host %s registered to plugin %s", host.String(), name)
		}
	}

	s.Plugins = plugs

	var listenIP string

	if listenIP = s.Opts.Get("listen.dev", "").String(); listenIP != "" {
		if listenIP, err = utils.GetInterfaceIpv4Addr(listenIP); err != nil {
			log.Error().Err(err).Msgf("failed to get ipv4 address from device: %s", listenIP)
			return err
		}
	} else {
		listenIP = s.Opts.Get("listen.ip", "").String() // Either it will use the IP address provided in the config or listen on all devices
	}
	s.Addr = listenIP

	portsMap := map[int]struct{}{}
	for _, plug := range s.Plugins {
		// Secure ports (HTTPS/TLS)
		ports := plug.Ports(true)
		for _, port := range ports {
			portsMap[port] = struct{}{}
		}

		// Insecure ports (HTTP/Plain text)
		ports = plug.Ports(false)
		for _, port := range ports {
			portsMap[port] = struct{}{}
		}
	}

	s.Ports = make([]int, len(portsMap))
	i := 0
	for port := range portsMap {
		s.Ports[i] = port
		i++
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.ctx = ctx
	s.cancel = cancel

	return nil
}

func (s *ProxyServer) Start() (err error) {

	hsErrChan := make(chan error, len(s.Ports))

	for _, port := range s.Ports {
		hs := &http.Server{
			Addr:        fmt.Sprintf("%s:%d", s.Addr, port),
			BaseContext: func(l net.Listener) context.Context { return s.ctx },
		}

		s.wg.Add(1)
		go func(hs *http.Server, hsErrChan chan<- error) {
			defer s.wg.Done()
			var l *Listener

			l, err = Listen("tcp", hs.Addr)
			if err != nil {
				err = xerrors.Errorf("%s listen tcp failure %w", hs.Addr, err)
				hsErrChan <- err
				return
			}

			l.HandleRawConnection = s.HandleRawConnection

			log.Debug().Msgf("%s serving requests on %s", s.Name, hs.Addr)
			hs.Serve(l)
			log.Debug().Msgf("%s server listening on %s has shutdown", s.Name, hs.Addr)
			hsErrChan <- nil
		}(hs, hsErrChan)

		s.servers = append(s.servers, hs)
	}

	close(s.Started)
	s.wg.Wait()
	close(hsErrChan)

	var allErrors error
	for err := range hsErrChan {
		if err != nil {
			if allErrors != nil {
				allErrors = xerrors.Errorf("%w; %w", allErrors, err)
			} else {
				allErrors = err
			}

		}
	}

	return allErrors
}

func (s *ProxyServer) Stop() error {
	for _, server := range s.servers {
		server.Shutdown(context.Background())
	}

	log.Debug().Msgf("all %s listening servers have shutdown", s.Name)
	return nil
}

func (s *ProxyServer) IsStarted() chan struct{} {
	return s.Started
}

func (s *ProxyServer) DialProxyTimeout(network, address, proxy string, timeout time.Duration) (net.Conn, error) {
	var (
		err      error
		proxyURL *url.URL
	)

	proxyURL, err = utils.NormalizeURL(proxy)
	if err != nil {
		return nil, err
	}

	remoteURL, err := utils.NormalizeURL(address)
	if err != nil {
		return nil, err
	}

	proxyConn, err := net.DialTimeout(network, proxyURL.Host, timeout)
	if err != nil {
		err = xerrors.Errorf("dial proxy %s timeout %s", proxyURL.String(), timeout.String())
		return nil, err
	}

	defer func() {
		if err != nil {
			proxyConn.Close()
		}
	}()

	if proxyURL.Scheme == "https" {
		// Upgrade connection to TLS
		config := &tls.Config{InsecureSkipVerify: true}
		tlsClient := tls.Client(proxyConn, config)
		if err = tlsClient.Handshake(); err != nil {
			err = xerrors.Errorf("tls client handshake to proxy server %s failure %w", proxyURL.String(), err)
			return nil, err
		}

		proxyConn = net.Conn(tlsClient)
		_ = proxyConn
	}

	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: remoteURL.Host},
		Host:   remoteURL.Host,
		Header: make(http.Header),
	}

	if err = req.WriteProxy(proxyConn); err != nil {
		err = xerrors.Errorf("failed to send connect request to proxy %s %w", proxyURL.String(), err)
		return nil, err
	}

	br := bufio.NewReader(proxyConn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		err = xerrors.Errorf("failed to read response from proxy %s %w", proxyURL.String(), err)
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err = xerrors.Errorf("proxy %s failed to connect to remote host %d %s", proxyURL.String(), resp.StatusCode, resp.Status)
	}

	return proxyConn, nil
}

// HandleRawConnection allows the processing of a connection from a client and potentially to a remote host
// before any handshakes or protocols have begun. This allows the oppurtunity to do a direct transfer between hosts
// without any interception of the data.
// TLS connections can be proxied here without having to MITM the connection; i.e. they can remain secure
// Plain HTTP requests can be proxied here and directly copied between clients and remote hosts, increasing efficiency
func (s *ProxyServer) HandleRawConnection(clientConn net.Conn, host string, port int, secure bool) (ok bool, err error) {
	plug := s.findPlugin(host, port, secure)
	if plug == nil {
		return false, xerrors.Errorf("no supporting plugins for %v %s:%d found", func() string {
			if secure {
				return "secure"
			} else {
				return "insecure"
			}
		}(), host, port)
	}

	// TODO abstract this code out so it can be used both here and in MITM code
	remoteHost, remotePort := plug.DirectRemote(host, port, secure)
	if remoteHost != "" {
		remoteURL := fmt.Sprintf("%s:%d", remoteHost, remotePort)
		proxyRawURL, err := plug.ProxyURL(host, port, secure)
		if err != nil {
			return false, err
		}

		var remoteConn net.Conn
		if len(proxyRawURL) > 0 {
			proxyURL, err := utils.NormalizeURL(proxyRawURL)
			if err != nil {
				return false, err
			}

			remoteConn, err = s.DialProxyTimeout("tcp", remoteURL, proxyURL.String(), time.Second*5)
			if err != nil {
				return false, err
			}
		} else {
			remoteConn, err = net.DialTimeout("tcp", remoteURL, time.Second*5)
			if err != nil {
				return false, err
			}
		}

		defer remoteConn.Close()
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			io.Copy(clientConn, remoteConn)
			clientConn.(CloseWriter).CloseWrite()
			wg.Done()
		}()
		go func() {
			io.Copy(remoteConn, clientConn)
			remoteConn.(CloseWriter).CloseWrite()
			wg.Done()
		}()

		wg.Wait()
		return true, nil
	} else {
		// This means that this plugin's hosts do not support direct connections and will need further processing
		return false, nil // Not handled, but no error occurred
	}
}

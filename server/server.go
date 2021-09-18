package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"hiddenbridge/options"
	"hiddenbridge/plugins"
	"hiddenbridge/utils"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
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
	Ports   []string

	ctx context.Context
	// cancel  context.CancelFunc
	wg      sync.WaitGroup
	servers []*http.Server

	caCert    tls.Certificate
	siteCerts map[string]*tls.Certificate

	siteProxies map[string]*httputil.ReverseProxy
}

func init() {
	ClosedChan = make(chan struct{})
	close(ClosedChan)
}

func NewProxyServer() *ProxyServer {
	return &ProxyServer{
		Name:        "hiddenbridge",
		Started:     make(chan struct{}),
		wg:          sync.WaitGroup{},
		servers:     []*http.Server{},
		siteCerts:   map[string]*tls.Certificate{},
		siteProxies: map[string]*httputil.ReverseProxy{},
	}
}

func (s *ProxyServer) parseYamlConfig(yamConfigFile string) (serverConfig map[string]interface{}, pluginsConfig map[string]interface{}, err error) {

	var config map[string]map[string]interface{}
	var yamlFile []byte

	if yamlFile, err = ioutil.ReadFile(yamConfigFile); err != nil {
		err = xerrors.Errorf("failed to read config file %s: %w", yamConfigFile, err)
		return
	}

	if err = yaml.Unmarshal(yamlFile, &config); err != nil {
		err = xerrors.Errorf("failed to unmarshal config %s: %w", yamConfigFile, err)
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

func (s *ProxyServer) findPlugin(hostURL *url.URL) plugins.Plugin {
	var (
		ok   bool
		plug plugins.Plugin
	)

	searchHost := hostURL.Hostname()
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

	if plug != nil && plug.HandlesURL(hostURL) {
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
			err = xerrors.Errorf("failed to get ipv4 address from device %s: %w", listenIP, err)
			return err
		}
	} else {
		listenIP = s.Opts.Get("listen.ip", "").String() // Either it will use the IP address provided in the config or listen on all devices
	}
	s.Addr = listenIP

	portsMap := map[string]struct{}{}
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

	s.Ports = make([]string, len(portsMap))
	i := 0
	for port := range portsMap {
		s.Ports[i] = port
		i++
	}

	certFile := s.Opts.Get("ca.cert", "").String()
	keyFile := s.Opts.Get("ca.key", "").String()

	caCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		err = xerrors.Errorf("failed to load X509 key pair cert '%s' key '%s': %w", certFile, keyFile, err)
		return err
	}

	s.caCert = caCert
	s.ctx = context.Background()

	return nil
}

func (s *ProxyServer) Start() (err error) {

	hsErrChan := make(chan error, len(s.Ports))

	for _, port := range s.Ports {
		hs := &http.Server{
			Addr:        fmt.Sprintf("%s:%s", s.Addr, port),
			BaseContext: func(l net.Listener) context.Context { return s.ctx },
			Handler:     s,
		}

		s.wg.Add(1)
		go func(hs *http.Server, hsErrChan chan<- error) {
			defer s.wg.Done()
			var l *Listener

			l, err = Listen("tcp", hs.Addr)
			if err != nil {
				err = xerrors.Errorf("%s listen tcp failure: %w", hs.Addr, err)
				hsErrChan <- err
				return
			}

			l.HandleRawConnection = s.HandleRawConnection
			l.GetCertificate = s.GetCertificate

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
				allErrors = xerrors.Errorf("%w: %w", allErrors, err)
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

func (s *ProxyServer) DialProxyTimeout(network string, remoteAddress, proxy *url.URL, timeout time.Duration) (net.Conn, error) {
	var (
		err      error
		proxyURL *url.URL
	)

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
			err = xerrors.Errorf("tls client handshake to proxy server %s failure: %w", proxyURL.String(), err)
			return nil, err
		}

		proxyConn = net.Conn(tlsClient)
	}

	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: remoteAddress.Host},
		Host:   remoteAddress.Host,
		Header: make(http.Header),
	}

	if err = req.WriteProxy(proxyConn); err != nil {
		err = xerrors.Errorf("failed to send connect request to proxy %s: %w", proxyURL.String(), err)
		return nil, err
	}

	br := bufio.NewReader(proxyConn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		err = xerrors.Errorf("failed to read response from proxy %s: %w", proxyURL.String(), err)
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
func (s *ProxyServer) HandleRawConnection(clientConn net.Conn, hostURL *url.URL) (ok bool, err error) {
	plug := s.findPlugin(hostURL)
	if plug == nil {
		log.Warn().Msgf("%s server has no supporting plugins for %s", s.Name, hostURL.String())

		return false, nil
	}

	// TODO abstract this code out so it can be used both here and in MITM code
	remoteURL, err := plug.DirectRemote(hostURL)
	if err != nil {
		return false, err
	}

	if remoteURL != nil {
		proxyURL, err := plug.ProxyURL(remoteURL)
		if err != nil {
			return false, err
		}

		var remoteConn net.Conn
		if proxyURL != nil {
			remoteConn, err = s.DialProxyTimeout("tcp", remoteURL, proxyURL, time.Second*5)
			if err != nil {
				return false, err
			}
		} else {
			remoteConn, err = net.DialTimeout("tcp", remoteURL.Host, time.Second*5)
			if err != nil {
				return false, err
			}
		}

		defer remoteConn.Close()
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			io.Copy(clientConn, remoteConn)
			clientConn.(CloseWriter).CloseWrite()

		}()
		go func() {
			wg.Done()
			io.Copy(remoteConn, clientConn)
			remoteConn.(CloseWriter).CloseWrite()
		}()

		wg.Wait()
		return true, nil
	} else {
		// This means that this plugin's hosts do not support direct connections and will need further processing
		return false, nil // Not handled, but no error occurred
	}
}

// GetCertificate returns an appropriate tls certificate base on information from the ClientHelloInfo
func (s *ProxyServer) GetCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// Use hiddenbridge's CA certificate to dynamically generate and sign the server certificate for this request
	// cache certificates for efficiency

	if siteCert, ok := s.siteCerts[chi.ServerName]; ok {
		return siteCert, nil
	}

	log.Debug().Msgf("%s server generating site cert %s", s.Name, chi.ServerName)

	// from https://shaneutt.com/blog/golang-ca-and-signed-cert-go/
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:  []string{"Default Company Ltd"},
			Country:       []string{"XX"},
			Province:      []string{""},
			Locality:      []string{"Default City"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback, chi.Conn.LocalAddr().(*net.TCPAddr).IP},
		DNSNames:     []string{chi.ServerName},
		NotBefore:    time.Now().AddDate(0, 0, -7),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		err = xerrors.Errorf("%s server generating site rsa key failure: %w", s.Name, err)
		return nil, err
	}

	caCert, err := x509.ParseCertificate(s.caCert.Certificate[0])
	if err != nil {
		err = xerrors.Errorf("%s server x509 parse ca certificate failure: %w", s.Name, err)
		return nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certPrivKey.PublicKey, s.caCert.PrivateKey)
	if err != nil {
		err = xerrors.Errorf("%s server creating site certificate failure: %w", s.Name, err)
		return nil, err
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	siteCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	if err != nil {
		err = xerrors.Errorf("%s server site X509 key pair failure: %w", s.Name, err)
		return nil, err
	}

	s.siteCerts[chi.ServerName] = &siteCert

	return &siteCert, nil
}

// ServeHTTP handles the request and returns the response to client
func (s *ProxyServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	var (
		plug         plugins.Plugin
		origReqURL   *url.URL
		curentReqURL url.URL
		currentPlug  plugins.Plugin
	)

	reqURL, err := utils.URLFromRequest(req)
	if err != nil {
		http.Error(rw, xerrors.Errorf("%s server failed to parse request url %s: %w", s.Name, req.Host, err).Error(), http.StatusInternalServerError)
		return
	}
	origReqURL = reqURL
	curentReqURL = *origReqURL

	for {
		plug = s.findPlugin(&curentReqURL)
		if plug == nil {
			// No plugin, we can assume we now have the final end point
			break
		}

		currentPlug = plug

		reqURL, req, err = plug.HandleRequest(reqURL, req)
		if err != nil {
			http.Error(rw, xerrors.Errorf("%s server %s plugin failed to handle url %s: %w", s.Name, plug.Name(), req.Host, err).Error(), http.StatusInternalServerError)
			return
		}

		if reqURL != nil {
			req.Host = reqURL.Host
		}

		if reqURL == nil || *reqURL == curentReqURL {
			// reqURL is now nil or didn't change we are now ready to process the response
			break
		}

		curentReqURL = *reqURL
	}

	if currentPlug == nil {
		http.Error(rw, fmt.Sprintf("%s server does not support url %s", s.Name, curentReqURL.String()), http.StatusNotFound)
		return
	}

	if reqURL != nil {
		if *origReqURL == *reqURL {
			err = xerrors.Errorf("recursive request")
			log.Error().Err(err).Msgf("%s server failed to proxy url %s", s.Name, reqURL.String())
			http.Error(rw, xerrors.Errorf("%s server failed to proxy url %s: %w", s.Name, reqURL.String(), err).Error(), http.StatusMisdirectedRequest)
			return
		}

		proxyURL, err := currentPlug.ProxyURL(reqURL)
		if err != nil {
			http.Error(rw, xerrors.Errorf("%s server %s plugin failed to check proxy url %s: %w", s.Name, plug.Name(), reqURL.String(), err).Error(), http.StatusInternalServerError)
			return
		}

		tlsConfig := &tls.Config{}
		if req.TLS != nil {
			tlsConfig.InsecureSkipVerify = true
		}

		rp, ok := s.siteProxies[reqURL.String()]
		if !ok {
			rp = httputil.NewSingleHostReverseProxy(reqURL)
			rp.Transport = &http.Transport{
				Proxy:           http.ProxyURL(proxyURL),
				TLSClientConfig: tlsConfig,
			}
			rp.ModifyResponse = s.ModifyResponse
			s.siteProxies[reqURL.String()] = rp
		}

		rp.ServeHTTP(rw, req)
	}

	log.Debug().Msgf("R: %+v", req)
	rw.WriteHeader(http.StatusAccepted)
}

func (s *ProxyServer) ModifyResponse(resp *http.Response) error {
	req := resp.Request
	reqURL, err := utils.URLFromRequest(req)
	if err != nil {
		return xerrors.Errorf("%s server failed to parse url %s: %w", s.Name, req.Host, err)
	}

	plug := s.findPlugin(reqURL)
	if plug == nil {
		// No plugin, so nothing to do
		return nil
	}

	return plug.HandleResponse(reqURL, resp)
}

func (s *ProxyServer) ErrorHandler(rw http.ResponseWriter, req *http.Request, err error) {
	reqURL, parseErr := utils.URLFromRequest(req)

	if parseErr != nil {
		log.Error().Err(parseErr).Msgf("%s server failure to parse url from req %+v during response error handling", s.Name, req)
		http.Error(rw, xerrors.Errorf("%s server internal error during error handling of request and response processing: %w", s.Name, parseErr).Error(), http.StatusInternalServerError)
		return
	}

	log.Error().Err(err).Msgf("%s server failure to handle proxying of request %s and processing response", s.Name, reqURL.String())
	http.Error(rw, xerrors.Errorf("%s server failure to handle proxying of request %s and processing response: %w", s.Name, reqURL.String(), err).Error(), http.StatusInternalServerError)
}

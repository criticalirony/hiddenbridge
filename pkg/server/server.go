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
	"hiddenbridge/pkg/options"
	"hiddenbridge/pkg/plugins"
	"hiddenbridge/pkg/server/request"
	"hiddenbridge/pkg/utils"
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

type BridgeServer struct {
	Name    string
	Opts    *options.OptionValue
	Plugins map[string]plugins.Plugin
	Started chan struct{}
	Addr    string
	Ports   map[string]struct{}

	ctx     context.Context
	wg      sync.WaitGroup
	servers []*http.Server

	caCert    tls.Certificate
	siteCerts map[string]*tls.Certificate

	// Caches per site reverse proxy servers
	reverseSiteProxies map[string]*httputil.ReverseProxy

	// Keeps track of IPs that point back to this server
	// used to prevent recursive requests
	localIPs map[string]struct{}
}

func init() {
	ClosedChan = make(chan struct{})
	close(ClosedChan)
}

func NewBridgeServer() *BridgeServer {
	return &BridgeServer{
		Name:               "hiddenbridge",
		Started:            make(chan struct{}),
		wg:                 sync.WaitGroup{},
		servers:            []*http.Server{},
		siteCerts:          map[string]*tls.Certificate{},
		reverseSiteProxies: map[string]*httputil.ReverseProxy{},
	}
}

func (s *BridgeServer) parseYamlConfig(yamConfigFile string) (opts *options.OptionValue, err error) {

	var config interface{}
	var yamlFile []byte

	if yamlFile, err = ioutil.ReadFile(yamConfigFile); err != nil {
		err = xerrors.Errorf("failed to read config file %s: %w", yamConfigFile, err)
		return
	}

	if err = yaml.Unmarshal(yamlFile, &config); err != nil {
		err = xerrors.Errorf("failed to unmarshal config %s: %w", yamConfigFile, err)
		return
	}

	opts = &options.OptionValue{}
	if err = opts.Set("", config); err != nil {
		err = xerrors.Errorf("failed to initialize options: %w", err)
		opts = nil
		return
	}

	return
}

func (s *BridgeServer) findPlugin(hostURL *url.URL) plugins.Plugin {
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

func (s *BridgeServer) Init(configFile string) (err error) {
	var config *options.OptionValue

	if strings.HasSuffix(configFile, ".yml") || strings.HasSuffix(configFile, ".yaml") {
		if config, err = s.parseYamlConfig(configFile); err != nil {
			return
		}
	} else {
		err = xerrors.Errorf("unsupported config file %s", configFile)
		return
	}

	s.Opts = config.Get("global")

	// Initialize plugins
	plugs := map[string]plugins.Plugin{}
	protocols := []string{"https", "http"}
	// Effectively a set from a map.. set.. just a map without values
	portsSet := map[string]struct{}{}

	for name, plugNewFn := range plugins.PluginBuilder {
		plugOpts := config.Get(fmt.Sprintf("plugins[%s]", name))
		if plugOpts == nil {
			return xerrors.Errorf("%s contains no options for plugin %s", configFile, name)
		}

		plug := plugNewFn()
		plug.Init(plugOpts)

		hosts := plugOpts.Get("hosts").StringList()
		for _, host := range hosts {
			plugs[host] = plug
		}

		for _, protocol := range protocols {
			ports := plug.Ports(protocol)
			for _, port := range ports {
				portsSet[port] = struct{}{}
			}

			log.Info().Msgf("hosts: %v %s ports: %v registered to plugin: %s", hosts, protocol, ports, plug.Name())
		}
	}

	s.Plugins = plugs

	var listenIP string

	if listenIP = s.Opts.Get("listen.dev").String(); listenIP != "" {
		if listenIP, err = utils.GetInterfaceIpv4Addr(listenIP); err != nil {
			err = xerrors.Errorf("failed to get ipv4 address from device %s: %w", listenIP, err)
			return err
		}
	} else {
		listenIP = s.Opts.GetDefault("listen.ip", "").String() // Either it will use the IP address provided in the config or listen on all devices
	}

	s.Addr = listenIP
	s.Ports = portsSet
	certFile := s.Opts.Get("ca.cert").String()
	keyFile := s.Opts.Get("ca.key").String()

	caCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		err = xerrors.Errorf("failed to load X509 key pair cert '%s' key '%s': %w", certFile, keyFile, err)
		return err
	}

	s.caCert = caCert
	s.ctx = context.Background()
	s.localIPs = utils.GetLocalIPs()

	// Also include external IPs
	externalIPs := s.Opts.GetDefault("ips.external", nil).StringList()
	for _, ip := range externalIPs {
		s.localIPs[ip] = struct{}{}
	}

	return nil
}

func (s *BridgeServer) Start() (err error) {

	hsErrChan := make(chan error, len(s.Ports))

	// s.Ports is a set (map with no values) so we iterate over its keys, not values
	for port := range s.Ports {
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
			err = hs.Serve(l)
			if err != nil {
				log.Error().Err(err).Msgf("%s server listening on %s has failed", s.Name, hs.Addr)
			}
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

func (s *BridgeServer) Stop() error {
	wait := 15 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()

	for _, server := range s.servers {
		server.Shutdown(ctx)
	}

	log.Debug().Msgf("all %s listening servers have shutdown", s.Name)
	return nil
}

func (s *BridgeServer) IsStarted() chan struct{} {
	return s.Started
}

func (s *BridgeServer) DialProxyTimeout(network string, remoteAddress, proxy *url.URL, timeout time.Duration) (net.Conn, error) {
	proxyConn, err := net.DialTimeout(network, proxy.Host, timeout)
	if err != nil {
		err = xerrors.Errorf("dial proxy %s timeout %s", proxy.String(), timeout.String())
		return nil, err
	}

	defer func() {
		if err != nil {
			proxyConn.Close()
		}
	}()

	if proxy.Scheme == "https" {
		// Upgrade connection to TLS
		config := &tls.Config{InsecureSkipVerify: true}
		tlsClient := tls.Client(proxyConn, config)
		if err = tlsClient.Handshake(); err != nil {
			err = xerrors.Errorf("tls client handshake to server %s failure: %w", proxy.String(), err)
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
		err = xerrors.Errorf("failed to send connect request to proxy %s: %w", proxy.String(), err)
		return nil, err
	}

	br := bufio.NewReader(proxyConn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		err = xerrors.Errorf("failed to read response from proxy %s: %w", proxy.String(), err)
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err = xerrors.Errorf("proxy %s failed to connect to remote host %d %s", proxy.String(), resp.StatusCode, resp.Status)
	}

	return proxyConn, nil
}

// HandleRawConnection allows the processing of a connection from a client and potentially to a remote host
// before any handshakes or protocols have begun.

// This allows the oppurtunity to do a direct transfer between hosts without any interception of the data.
// TLS connections can be proxied here without having to MITM the connection; i.e. they can remain secure
// Plain HTTP requests can be proxied here and directly copied between clients and remote hosts, increasing efficiency
func (s *BridgeServer) HandleRawConnection(clientConn net.Conn, hostURL *url.URL) (ok bool, err error) {
	if hostURL.Hostname() == "" {
		// This can happen if we don't have SNI for TLS or a Host header in HTTP
		hostname := s.Opts.Get("host.default").String()
		if hostname == "" {
			return false, xerrors.Errorf("%s server handle raw connection hostname not available", s.Name)
		}

		hostURL.Host = fmt.Sprintf("%s:%s", hostname, hostURL.Port())
	}

	plug := s.findPlugin(hostURL)
	if plug == nil {
		log.Warn().Msgf("%s server has no supporting plugins for %s", s.Name, hostURL.String())

		return false, nil
	}

	// TODO abstract this code out so it can be used both here and in MITM code
	remoteURL, err := plug.RemoteURL(hostURL)
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
			if *remoteURL != *hostURL {
				remoteConn, err = net.DialTimeout("tcp", remoteURL.Host, time.Second*5)
				if err != nil {
					return false, err
				}
			} else {
				// TODO check the recursive here

				err = xerrors.Errorf("recursive request")
				return false, xerrors.Errorf("%s server failed to request url %s: %w", s.Name, hostURL.String(), err)
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

// GetCertificate returns an appropriate tls certificate based on information from the ClientHelloInfo
func (s *BridgeServer) GetCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// Use hiddenbridge's CA certificate to dynamically generate and sign the server certificate for this request
	// cache certificates for efficiency.
	// Also allow plugins to provide their own certificate information
	var (
		err      error
		ok       bool
		siteCert *tls.Certificate
	)

	if chi.ServerName == "" {
		chi.ServerName = s.Opts.Get("host.default").String() // No SNI information was received, lets try the default host
	}

	if siteCert, ok = s.siteCerts[chi.ServerName]; ok {
		log.Debug().Msgf("%s server providing cached site cert %s", s.Name, chi.ServerName)
		return siteCert, nil
	}

	hostURL, err := utils.NormalizeURL(chi.ServerName)
	if err != nil {
		return nil, xerrors.Errorf("%s server could not normalize host: %s to url", s.Name, chi.ServerName)
	}

	hostURL.Scheme = "https"
	port := chi.Conn.LocalAddr().(*net.TCPAddr).Port
	hostURL.Host = fmt.Sprintf("%s:%d", hostURL.Hostname(), port)

	// A plugin may also serve its own certificate
	plug := s.findPlugin(hostURL)
	if plug != nil {
		if siteCert, err = plug.HandleCertificate(hostURL.Hostname()); err != nil {
			return nil, xerrors.Errorf("%s plugin could not handle certificate for %s", plug.Name(), chi.ServerName)
		}

		if siteCert != nil {
			log.Debug().Msgf("%s plugin handled site cert %s request", plug.Name(), chi.ServerName)
			s.siteCerts[chi.ServerName] = siteCert
			return siteCert, nil
		}
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
			// CommonName:    chi.ServerName,
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback, chi.Conn.LocalAddr().(*net.TCPAddr).IP},
		DNSNames:     []string{chi.ServerName},
		NotBefore:    time.Now().AddDate(0, 0, -7),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, // Very important Centos 7 needs "x509.KeyUsageKeyEncipherment"
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

	x509cert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	if err != nil {
		err = xerrors.Errorf("%s server site X509 key pair failure: %w", s.Name, err)
		return nil, err
	}

	s.siteCerts[chi.ServerName] = &x509cert

	return &x509cert, nil
}

// ServeHTTP handles the request and returns the response to client
func (s *BridgeServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var (
		plug         plugins.Plugin
		origReqURL   url.URL
		curentReqURL url.URL
		newReq       *http.Request
	)

	reqURL, err := utils.URLFromRequest(req)
	if err != nil {
		http.Error(w, xerrors.Errorf("%s server failed to parse request url %s: %w", s.Name, req.Host, err).Error(), http.StatusInternalServerError)
		return
	}
	origReqURL = *reqURL
	curentReqURL = origReqURL

	// This list keeps track of the plugins that have handled this request.
	// This list is played in reverse when modifying the response
	pluginsList := []plugins.Plugin{}

	// This set keeps track of hosts that have been handled
	// This prevents plugins from re-handling hosts, if a plugin puts an old host back into the request
	// :a use case for this is:
	// * Plugin A forwards data on to Plugin B. It replaces the request's host with a known host that will be handled by Plugin B
	//   and embeds the original host in the request; i.e. context or as a query parameter etc.
	// * Plugin B handles the request but wants to forward the request on to the original host in the request,
	//   but not send it back to Plugin A. It puts the original host back into the request from its embeded data.
	// * This server sees that the original host has already been handled and assumes its to be forwarded on upstream
	hostsList := map[string]struct{}{}

	reqCtx := request.RequestContext{}
	req = req.WithContext(context.WithValue(req.Context(), request.ReqContextKey, reqCtx))

	// plugins can set this in the request context if they'd prefer to specify the next plugin in the chain
	var pluginChain string

	for {
		plug = nil

		// Check if this is a plugin chain request
		if pluginChain != "" {
			plug = s.findPlugin(&url.URL{
				Host: pluginChain,
			})

			// Remove plugin chains from context to prevent cycles
			delete(reqCtx, "chain")
			pluginChain = ""
		}

		// Check if this is a normal pluin request
		if plug == nil {
			plug = s.findPlugin(&curentReqURL)
		}

		if plug == nil {
			// No plugin, we can assume we now have the final end point
			break
		}

		hostsList[reqURL.Hostname()] = struct{}{}
		reqURL, newReq, err = plug.HandleRequest(reqURL, req)
		if err != nil {
			http.Error(w, xerrors.Errorf("%s server %s plugin failed to handle url %s: %w", s.Name, plug.Name(), req.Host, err).Error(), http.StatusInternalServerError)
			return
		}

		if newReq != nil {
			req = newReq
		}

		pluginsList = append(pluginsList, plug)

		if reqURL != nil {
			req.Host = reqURL.Host
		}

		if utils.As(reqCtx["chain"], &pluginChain) && pluginChain != "" {
			// The last plugin registered a chain plugin, so we need to do at least one more iteration
			continue
		}

		if reqURL == nil || reqURL.Host == curentReqURL.Host {
			// reqURL is now nil or host hasn't changed we are now ready to process the response
			break
		}

		if _, ok := hostsList[reqURL.Hostname()]; ok {
			// reqURL now has a host that has already been handled. We are now ready to process the response
			break
		}

		curentReqURL = *reqURL
	}

	if plug == nil {
		http.Error(w, fmt.Sprintf("%s server does not support url %s", s.Name, curentReqURL.String()), http.StatusNotFound)
		return
	}

	if reqURL != nil {
		// Start looking for proxy - first find plugin that holds possilbe proxy URL
		plug = s.findPlugin(&curentReqURL)
		if plug == nil {
			// No plugin, we can assume we now have the final end point
			http.Error(w, xerrors.Errorf("%s server %s plugin failed to check proxy url %s: %w", s.Name, plug.Name(), reqURL.String(), err).Error(), http.StatusInternalServerError)
			return
		}

		// Ask plugin if this URL needs to be proxied
		proxyURL, err := plug.ProxyURL(reqURL)
		if err != nil {
			http.Error(w, xerrors.Errorf("%s server %s plugin failed to check proxy url %s: %w", s.Name, plug.Name(), reqURL.String(), err).Error(), http.StatusInternalServerError)
			return
		}

		// A proxy URL is not needed, but the request host hasn't changed... this might be a cycle
		// its not a cycle if this server resolves the host differently to the requesting client
		if proxyURL == nil && (origReqURL.Host == reqURL.Host) {
			// Resolve host to an IP
			addrs, err := net.LookupHost(origReqURL.Hostname())
			if err != nil {
				err = xerrors.Errorf("internal hostname resolutuion failure")
				log.Error().Err(err).Msgf("%s server failed to resolve request url %s", s.Name, reqURL.String())
				http.Error(w, xerrors.Errorf("%s server failed to resolve request url %s: %w", s.Name, reqURL.String(), err).Error(), http.StatusMisdirectedRequest)
				return
			}

			// Check IP to see if its any we're hosting
			for _, addr := range addrs {
				if _, ok := s.localIPs[addr]; ok {
					// We really do seem to have a recursive request
					err = xerrors.Errorf("recursive request")
					log.Error().Err(err).Msgf("%s server failed to request url %s", s.Name, reqURL.String())
					http.Error(w, xerrors.Errorf("%s server failed to request url %s: %w", s.Name, reqURL.String(), err).Error(), http.StatusMisdirectedRequest)
					return
				}
			}
		}

		tlsConfig := &tls.Config{}
		if req.TLS != nil {
			tlsConfig.InsecureSkipVerify = true
		}

		rsp, ok := s.reverseSiteProxies[reqURL.Host]
		if !ok {
			revProxy := &url.URL{
				Scheme: reqURL.Scheme,
				Host:   reqURL.Host,
			}

			rsp = httputil.NewSingleHostReverseProxy(revProxy)
			rsp.Transport = &http.Transport{
				Proxy:           http.ProxyURL(proxyURL),
				TLSClientConfig: tlsConfig,
			}
			rsp.ModifyResponse = s.ModifyResponse
			s.reverseSiteProxies[reqURL.Host] = rsp
		}

		// Save the visitied plugins in the request context so it can be used by the response handlers
		reqCtx["pluginslist"] = pluginsList

		*req.URL = *reqURL  // Shallow copy
		req.URL.Scheme = "" // Remove host and scheme, it breaks the way reverse proxy works
		req.URL.Host = ""

		// req.RequestURI = utils.TargetFromURL(reqURL)
		rsp.ServeHTTP(w, req)
		return
	}

	// Save the visitied plugins in the request context so it can be used by the response handlers
	reqCtx["pluginslist"] = pluginsList
	resp := &http.Response{
		Request: req,
		Body:    http.NoBody,
	}

	// Call response handlers to allow customization of responses
	if err = s.ModifyResponse(resp); err != nil {
		s.ErrorHandler(w, req, err)
		return
	}

	// Delete existing headers
	w.Header().Del("Content-Type")
	w.Header().Del("Connection")

	// Copy headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	w.WriteHeader(resp.StatusCode)

	if resp.Body != http.NoBody {
		if _, err := io.CopyBuffer(w, resp.Body, nil); err != nil {
			log.Error().Err(err).Msgf("failed to send response body for request %s", reqURL.String())
		}
	}
}

func (s *BridgeServer) ModifyResponse(resp *http.Response) error {
	var (
		err    error
		ok     bool
		reqURL *url.URL
		reqCtx request.RequestContext
	)

	req := resp.Request
	reqCtx, ok = req.Context().Value(request.ReqContextKey).(request.RequestContext)
	if !ok {
		return xerrors.Errorf("request context not available")
	}

	var pluginsList []plugins.Plugin
	if !utils.As(reqCtx["pluginslist"], &pluginsList) || pluginsList == nil {
		return xerrors.Errorf("plugins list not available")
	}

	if len(pluginsList) == 0 {
		// No plugin, so nothing to do
		return nil
	}

	rrc := utils.NewReReadCloser(resp.Body)
	resp.Body = rrc

	modResponseWriter := NewResponseModifier(resp)

	// Iterate the visited plugins in reverse order.. i.e. handle responses in the opposite direction than the requests
	// Requests are processed in FIFO, responses are processed in LIFO
	for i := len(pluginsList) - 1; i >= 0; i-- {
		plug := pluginsList[i]

		if err = plug.HandleResponse(modResponseWriter, req, reqCtx, resp.Body, resp.StatusCode); err != nil {
			return xerrors.Errorf("failed to handle response for request %s: %w", reqURL.String(), err)
		}

		// Reset the response body, ready for the next plugin
		resp.Body.(utils.ReReadCloser).Reset()

		// Once a plugin has written a body to the response, its not safe for any other plugin to further modify the response
		if modResponseWriter.Written() > 0 {
			// The response writer has been written to, so other plugins can no longer modify the response
			break
		}
	}

	if resp, err = modResponseWriter.Result(); err != nil {
		return xerrors.Errorf("failed to get modified response result: %w", err)
	}

	if resp.ProtoAtLeast(1, 1) {
		resp.Header.Set("Connection", "close")
	}

	return err
}

func (s *BridgeServer) ErrorHandler(w http.ResponseWriter, req *http.Request, err error) {
	reqURL, parseErr := utils.URLFromRequest(req)

	if parseErr != nil {
		log.Error().Err(parseErr).Msgf("%s server failure to parse url from req %+v during response error handling", s.Name, req)
		http.Error(w, xerrors.Errorf("%s server internal error during error handling of request and response processing: %w", s.Name, parseErr).Error(), http.StatusInternalServerError)
		return
	}

	log.Error().Err(err).Msgf("%s server failure to handle proxying of request %s and processing response", s.Name, reqURL.String())
	http.Error(w, xerrors.Errorf("%s server failure to handle proxying of request %s and processing response: %w", s.Name, reqURL.String(), err).Error(), http.StatusInternalServerError)
}

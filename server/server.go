package server

import (
	"context"
	"fmt"
	"hiddenbridge/options"
	"hiddenbridge/plugins"
	"hiddenbridge/utils"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"sync"

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

type Listener struct {
	inner net.Listener
}

func init() {
	ClosedChan = make(chan struct{})
	close(ClosedChan)
}

func NewServer() *ProxyServer {
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
			var l net.Listener

			l, err = Listen("tcp", hs.Addr)
			if err != nil {
				err = xerrors.Errorf("%s listen tcp failure %w", hs.Addr, err)
				hsErrChan <- err
				return
			}

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

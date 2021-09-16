package utils

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	"golang.org/x/xerrors"
)

// GetInterfaceIpv4Addr gets the first associated IPv4 address of a network interface
// from https://gist.github.com/schwarzeni/f25031a3123f895ff3785970921e962c
func GetInterfaceIpv4Addr(interfaceName string) (addr string, err error) {
	var (
		ief      *net.Interface
		addrs    []net.Addr
		ipv4Addr net.IP
	)

	if ief, err = net.InterfaceByName(interfaceName); err != nil { // get interface
		return
	}
	if addrs, err = ief.Addrs(); err != nil { // get addresses
		return
	}
	for _, addr := range addrs { // get ipv4 address
		if ipv4Addr = addr.(*net.IPNet).IP.To4(); ipv4Addr != nil {
			break
		}
	}
	if ipv4Addr == nil {
		return "", xerrors.Errorf("ipv4 address for %s not found", interfaceName)
	}

	return ipv4Addr.String(), nil
}

// Done is a non-blocking function that returns true if the context has been canceled.
func Done(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func NormalizeURL(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		// This occurs when there is no sheme and the host starts with a number; i.e. an IP address
		if !strings.HasPrefix(rawURL, "http") {
			if !strings.HasSuffix(rawURL, ":443") {
				rawURL = "http://" + rawURL
			} else {
				rawURL = "https://" + rawURL
			}

			u, err = url.Parse(rawURL)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	if len(u.Scheme) == 0 && len(u.Host) == 0 && len(u.Path) > 0 {
		// Assume no scheme and no port
		// u.path == bob.com
		rawURL = fmt.Sprintf("http://%s:80", rawURL)
	} else if len(u.Scheme) > 0 && len(u.Host) == 0 {
		// Assume no scheme (might or might not have a port!)
		// u.scheme == bob.com

		host, port, _ := net.SplitHostPort(rawURL)
		if len(host) == 0 {
			host = rawURL
		}

		if len(port) == 0 {
			port = "80"
		}

		scheme := "http"
		if port == "443" {
			scheme = "https" // Assume if we provide port 443 but no scheme, we really do mean https
		}

		rawURL = fmt.Sprintf("%s://%s:%s", scheme, host, port)
	} else if len(u.Scheme) > 0 && len(u.Port()) == 0 {
		// Assume no port
		// u.scheme == http, u.host == bob.com

		port := "80"
		if u.Scheme == "https" {
			port = "443"
		}

		rawURL = fmt.Sprintf("%s://%s:%s", u.Scheme, u.Host, port)
	}

	u, err = url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	if len(u.Scheme) == 0 || len(u.Hostname()) == 0 || len(u.Port()) == 0 {
		err = xerrors.Errorf("malformed url %s", u.String())
		return nil, err
	}

	return u, nil
}

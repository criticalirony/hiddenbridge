package utils

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"

	"github.com/rs/zerolog/log"

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

func SplitHostPath(rawURL string) (host, path string) {
	idx := strings.Index(rawURL, "/")
	if idx < 0 {
		return rawURL, ""
	}

	return rawURL[:idx], rawURL[idx:]
}

func NormalizeURL(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		// This occurs when there is no sheme and the host starts with a number; i.e. an IP address
		if !strings.HasPrefix(rawURL, "http") {
			host, _ := SplitHostPath(rawURL)
			if !strings.HasSuffix(host, ":443") {
				rawURL = "http://" + rawURL
			} else {
				rawURL = "https://" + rawURL
			}

			u, err = url.Parse(rawURL)
			if err != nil {
				return nil, xerrors.Errorf("failed to parse url %s: %s", rawURL, err)
			}
		} else {
			return nil, xerrors.Errorf("failed to parse url %s: %s", rawURL, err)
		}
	}

	if len(u.Scheme) == 0 && len(u.Host) == 0 && len(u.Path) > 0 {
		// Assume no scheme and no port
		// u.path == bob.com
		host, path := SplitHostPath(rawURL)
		rawURL = fmt.Sprintf("http://%s:80%s", host, path)
	} else if len(u.Scheme) > 0 && len(u.Host) == 0 {
		// Assume no scheme (might or might not have a port!)
		host, port, _ := net.SplitHostPort(rawURL)
		port, path := SplitHostPath(port)

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

		rawURL = fmt.Sprintf("%s://%s:%s%s", scheme, host, port, path)
	} else if len(u.Scheme) > 0 && len(u.Port()) == 0 {
		// Assume no port
		// u.scheme == http, u.host == bob.com

		port := "80"
		if u.Scheme == "https" {
			port = "443"
		}

		rawURL = fmt.Sprintf("%s://%s:%s%s", u.Scheme, u.Host, port, u.Path)
	}

	u, err = url.Parse(rawURL)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse url %s: %s", rawURL, err)
	}

	if len(u.Scheme) == 0 || len(u.Hostname()) == 0 || len(u.Port()) == 0 {
		return nil, xerrors.Errorf("malformed url %s", u.String())
	}

	return u, nil
}

func URLFromRequest(r *http.Request) (*url.URL, error) {
	reqURL, err := NormalizeURL(r.Host)
	if err != nil {
		log.Error().Err(err).Msgf("failed to get normalized url %s", r.Host)
		err = xerrors.Errorf("failed to get normalized url %s: %w", r.Host, err)
		return nil, err
	}

	if r.TLS != nil {
		reqURL.Scheme = "https"
		if r.Host != reqURL.Host {
			reqURL.Host = fmt.Sprintf("%s:443", reqURL.Hostname())
		}
	} // valid values for http will be set by default from NormalizeURL

	r.Host = reqURL.Host

	reqURL.User = r.URL.User
	reqURL.Path = r.URL.Path
	reqURL.RawPath = r.URL.RawPath
	reqURL.ForceQuery = r.URL.ForceQuery
	reqURL.RawQuery = r.URL.RawQuery
	reqURL.Fragment = r.URL.Fragment
	reqURL.RawFragment = r.URL.RawFragment

	return reqURL, nil
}

func TargetFromURL(u *url.URL) string {
	if u == nil {
		return ""
	}

	var buf strings.Builder
	path := u.EscapedPath()
	if path != "" && path[0] != '/' && u.Host != "" {
		buf.WriteByte('/')
	}
	buf.WriteString(path)

	if u.ForceQuery || u.RawQuery != "" {
		buf.WriteByte('?')
		buf.WriteString(u.RawQuery)
	}
	if u.Fragment != "" {
		buf.WriteByte('#')
		buf.WriteString(u.EscapedFragment())
	}
	return buf.String()
}

// Query the runtime for the caller's package
// taken from: https://stackoverflow.com/a/56960913
func Package(frame int) string {
	pc, _, _, _ := runtime.Caller(frame)
	parts := strings.Split(runtime.FuncForPC(pc).Name(), ".")
	if len(parts) >= 1 {
		return parts[0]
	}
	return ""
}

func PackageAsName() string {
	var name string

	packagePath := Package(2)
	packageIdx := strings.LastIndex(packagePath, "/")
	if packageIdx >= 0 && len(packagePath) > packageIdx+1 {
		name = packagePath[packageIdx+1:]
	} else {
		name = packagePath
	}

	return name
}

// CopyBuffer returns any write errors or non-EOF read errors, and the amount
// of bytes written.
// taken from: go/src/net/http/httputil/reverseproxy.go:455
func CopyBuffer(dst io.Writer, src io.Reader, buf []byte) (int64, error) {
	if len(buf) == 0 {
		buf = make([]byte, 32*1024)
	}
	var written int64
	for {
		nr, rerr := src.Read(buf)
		if rerr != nil && rerr != io.EOF && rerr != context.Canceled {
			return -1, xerrors.Errorf("read error during buffer copy: %w", rerr)
		}
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if werr != nil {
				return written, werr
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				rerr = nil
			}
			return written, rerr
		}
	}
}

// Get list of local IP Addresses
// adapted from: https://stackoverflow.com/questions/23558425/how-do-i-get-the-local-ip-address-in-go
func GetLocalIPs() map[string]struct{} {
	result := map[string]struct{}{}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Error().Err(err).Msg("failed to get local interface addresses")
		return map[string]struct{}{}
	}

	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			result[ipnet.IP.String()] = struct{}{}
		}
	}

	return result
}

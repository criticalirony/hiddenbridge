package utils

import (
	"context"
	"net"

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

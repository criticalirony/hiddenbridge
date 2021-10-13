package server

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"hiddenbridge/pkg/utils"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/rs/zerolog/log"
	"golang.org/x/xerrors"
)

type tlsUpgradeError struct {
	err error
}

func (e tlsUpgradeError) Error() string   { return xerrors.Errorf("tls upgrade: %w", e.err).Error() }
func (e tlsUpgradeError) Timeout() bool   { return false }
func (e tlsUpgradeError) Temporary() bool { return true } // This allows the outer server to continue serving requests

type Listener struct {
	inner               net.Listener
	HandleRawConnection func(clientConn net.Conn, hostURL *url.URL) (ok bool, err error)
	GetCertificate      func(chi *tls.ClientHelloInfo) (*tls.Certificate, error)
}

func Listen(network, address string) (*Listener, error) {
	l := &Listener{}

	inner, err := net.Listen(network, address)
	if err != nil {
		err = xerrors.Errorf("failed to get tcp listener %s", err)
		return nil, err
	}

	l.inner = inner
	return l, nil
}

func (l *Listener) Accept() (net.Conn, error) {

	var (
		err         error
		innerConn   net.Conn
		wrappedConn net.Conn

		hdr []byte

		hostURL *url.URL
	)

acceptLoop:
	for {
		innerConn, err = l.inner.Accept()
		if err != nil {
			return nil, err
		}

		peekConn := NewPeekableConn(innerConn)
		hdr, err = peekConn.Peek(5)
		if err != nil {
			err = xerrors.Errorf("failed to initialize peekable conn: %w", err)
			break
		}

		log.Debug().Msgf("Accepted Connection: %s -> %s", innerConn.RemoteAddr().String(), innerConn.LocalAddr().String())

		port := strconv.Itoa(innerConn.LocalAddr().(*net.TCPAddr).Port)

		copiedBuffer := bytes.Buffer{}
		wrappedReader := io.TeeReader(peekConn, &copiedBuffer)

		var clientHello *tls.ClientHelloInfo

		if !connLooksLikeHTTP(hdr) {
			log.Debug().Msgf("peek header: %s", hdr)

			// This is most probably a TLS connection - check for a ClientHello message
			clientHello, err = ReadClientHello(bufio.NewReader(wrappedReader))
			if err != nil {
				err = xerrors.Errorf("failed to read client hello: %w", err)
				break
			}

			if clientHello.ServerName != "" {
				hostURL, err = utils.NormalizeURL(fmt.Sprintf("%s:%s", clientHello.ServerName, port))
				if err != nil {
					err = xerrors.Errorf("failed to normalize url: %w", err)
					break
				}
			} else {
				hostURL = &url.URL{}
			}
			hostURL.Scheme = "https"
		} else {
			var r *http.Request

			// This is a plain text HTTP message, find the HOST header
			r, err = http.ReadRequest(bufio.NewReader(wrappedReader))
			if err != nil {
				break
			}

			if r.Host != "" {
				if hostURL, err = utils.NormalizeURL(r.Host); err != nil {
					err = xerrors.Errorf("failed to normalize url: %w", err)
					break
				}
			} else {
				hostURL = &url.URL{}
			}
			hostURL.Scheme = "http"
		}

		hostURL.Host = fmt.Sprintf("%s:%s", hostURL.Hostname(), port)
		wrappedConn = NewMultiReaderConn(peekConn, &copiedBuffer)

		if l.HandleRawConnection != nil {
			ok, err := l.HandleRawConnection(wrappedConn, hostURL)
			if !ok && err != nil {
				log.Error().Err(err).Msgf("failure to handle incoming connection on %s", wrappedConn.LocalAddr().String())
				wrappedConn.Close()
				continue
			}

			if ok {
				if err != nil {
					log.Panic().Err(err).Msg("unexpected error occurred")
				}
			} else {
				// Raw connection was not handled, but no error this means we can pass the connection on to the http handler
				// for mitm processing
				break
			}
		} else {
			log.Warn().Msg("no registered connection handler connection will be intercepted")
			break
		}
	}

	if err != nil {
		log.Error().Err(err).Msgf("listener internal error: %+v", err)
		if wrappedConn != nil {
			wrappedConn.Close()
		} else if innerConn != nil {
			innerConn.Close()
		}

		// Reset and try again
		wrappedConn = nil
		innerConn = nil
		err = nil
		goto acceptLoop
	}

	if hostURL.Scheme == "https" {
		// Upgrade connection to TLS
		tlsConn, err := upgradeConnection(wrappedConn, l.GetCertificate)
		if err != nil {
			// Failed to upgrade connection
			wrappedConn.Close()
			err = &tlsUpgradeError{err: err}
			return nil, err
		}

		return tlsConn, nil
	}

	return wrappedConn, err
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (l *Listener) Close() error {
	return l.inner.Close()
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	return l.inner.Addr()
}

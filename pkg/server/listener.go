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
	inner net.Listener
	// HandleProxyConnection func(conn *net.Conn, hostURL *url.URL) (ok bool, err error)
	HandleRawConnection func(conn *net.Conn, hostURL *url.URL) (ok bool, err error)
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

// GetConnectionHost returns the target host for the connection
// HTTP: "host" header field
// TLS: client HELLO server name
func (l *Listener) GetConnectionHost(conn *net.Conn) (*url.URL, error) {
	_conn := *conn

	peekConn := NewPeekableConn(_conn)

	hdr, err := peekConn.Peek(5)
	if err != nil {
		return nil, xerrors.Errorf("failed to initialize peekable conn: %w", err)
	}

	connCopyBuffer := bytes.Buffer{}
	wrappedReader := io.TeeReader(peekConn, &connCopyBuffer)

	var hostURL *url.URL

	if !connLooksLikeHTTP(hdr) {
		// This is most probably a TLS connection - check for a ClientHello message
		clientHello, err := ReadClientHello(bufio.NewReader(wrappedReader))
		if err != nil {
			return nil, xerrors.Errorf("failed to read client hello: %w", err)
		}

		port := strconv.Itoa(_conn.LocalAddr().(*net.TCPAddr).Port)

		if clientHello.ServerName != "" {
			hostURL, err = utils.NormalizeURL(fmt.Sprintf("%s:%s", clientHello.ServerName, port))
			if err != nil {
				return nil, xerrors.Errorf("failed to normalize url: %w", err)
			}
		}
	} else {
		var req *http.Request

		// This is a plain text HTTP message, find the HOST header
		req, err = http.ReadRequest(bufio.NewReader(wrappedReader))
		if err != nil {
			return nil, xerrors.Errorf("failed to read http request: %w", err)
		}

		if req.Host != "" {
			if hostURL, err = utils.NormalizeURL(req.Host); err != nil {
				return nil, xerrors.Errorf("failed to normalize url: %w", err)
			}
		}
	}

	*conn = NewMultiReaderConn(peekConn, &connCopyBuffer) // Update conn - this effectively "resets" the conn back to an unread state
	return hostURL, nil
}

func (l *Listener) Accept() (net.Conn, error) {

	var (
		err     error
		conn    net.Conn
		hostURL *url.URL
	)

acceptLoop:
	conn, err = l.inner.Accept()
	if err != nil {
		return nil, err
	}

	log.Debug().Msgf("accepted connection: %s -> %s", conn.RemoteAddr().String(), conn.LocalAddr().String())

	// Connections can be:
	// 1. HTTP
	// 2. HTTPS
	// 3. Proxied over HTTP
	// 4. Proxied over HTTPS

	// Direct connections can be:
	// 1. HTTP (with HOST)
	// 2. TLS (with SNI)
	// - No protocol exchange is required. Raw read from client to remote host

	// Proxied "direct" connections can be:
	// 1. HTTP after parsing CONNECT request
	// 2. HTTPS ater TLS handshake/accepting and parsing CONNECT request

	hostURL, err = l.GetConnectionHost(&conn)
	if err != nil {
		conn.Close()
		log.Error().Err(err).Msgf("connection host: failed to retrieve host url: connection lost")
		goto acceptLoop // Try again
	}

	// localPort := strconv.Itoa(conn.LocalAddr().(*net.TCPAddr).Port)
	// if l.HandleProxyConnection != nil {
	// 	ok, err := l.HandleProxyConnection(&conn, hostURL)
	// 	if ok && err != nil {
	// 		// The incoming connection should have been handled, but we received an unexpected error
	// 		// this is a critical issue and probalby means a bug that needs fixing
	// 		log.Panic().Err(err).Msg("unexpected error occurred")
	// 	}

	// 	if err != nil {
	// 		// We couldn't handle this connection due to an error occurring.
	// 		// This could be anything; probably due to protocol error or connection instability.
	// 		// Just bail on this connection and try again
	// 		log.Error().Err(err).Msgf("failure to handle incoming connection on %s", conn.LocalAddr().String())
	// 		conn.Close()
	// 		goto acceptLoop
	// 	}
	// }

	if l.HandleRawConnection != nil {
		ok, err := l.HandleRawConnection(&conn, hostURL)
		if ok && err != nil {
			// The incoming connection should have been handled, but we received an unexpected error
			// this is a critical issue and probalby means a bug that needs fixing
			log.Panic().Err(err).Msg("unexpected error occurred")
		}

		if err != nil {
			// We couldn't handle this connection due to an error occurring.
			// This could be anything; probably due to protocol error or connection instability.
			// Just bail on this connection and try again
			log.Error().Err(err).Msgf("failure to handle incoming connection on %s", conn.LocalAddr().String())
			conn.Close()
		}

		// If the raw connection was handled without error, then its now the handler's responsibilty to close the connection
		// this is because most likely the handler will now be running in its own go-routine
		goto acceptLoop
	} else {
		log.Warn().Msg("no registered connection handler: connection will be intercepted")
	}

	log.Panic().Msg("TODO: finish implementing raw handler above!")

	if hostURL.Scheme == "https" {
		// Upgrade connection to TLS
		tlsConn, err := upgradeConnection(conn, l.GetCertificate)
		if err != nil {
			// Failed to upgrade connection
			conn.Close()
			err = &tlsUpgradeError{err: err}
			return nil, err
		}

		return tlsConn, nil
	}

	return conn, err
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

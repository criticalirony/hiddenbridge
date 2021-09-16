package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"

	"github.com/rs/zerolog/log"
	"golang.org/x/xerrors"
)

type Listener struct {
	inner               net.Listener
	HandleRawConnection func(clientConn net.Conn, host string, port int, secure bool) (ok bool, err error)
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
		wrappedConn net.Conn

		hdr []byte

		host string
		port int
	)

	for {
		innerConn, err := l.inner.Accept()
		if err != nil {
			return nil, err
		}

		peekConn := NewPeekableConn(innerConn)
		hdr, err = peekConn.Peek(5)
		if err != nil {
			return nil, err
		}

		log.Debug().Msgf("Accepted Connection: %v", innerConn.LocalAddr().String())

		var isSecure = false

		port = innerConn.LocalAddr().(*net.TCPAddr).Port

		copiedBuffer := bytes.Buffer{}
		wrappedReader := io.TeeReader(peekConn, &copiedBuffer)

		var clientHello *tls.ClientHelloInfo

		if !connLooksLikeHTTP(hdr) {
			// This is most probably a TLS connection - check for a ClientHello message
			clientHello, err = ReadClientHello(bufio.NewReader(wrappedReader))
			if err != nil {
				return nil, err
			}

			if host, _, err = net.SplitHostPort(clientHello.ServerName); err != nil {
				host = clientHello.ServerName
			}

			isSecure = true
		} else {
			// This is a plain text HTTP message, find the HOST header
			req, err := http.ReadRequest(bufio.NewReader(wrappedReader))
			if err != nil {
				return nil, err
			}

			if host, _, err = net.SplitHostPort(req.Host); err != nil {
				host = req.Host
			}
		}

		wrappedConn = NewMultiReaderConn(peekConn, &copiedBuffer)

		if l.HandleRawConnection != nil {
			ok, err := l.HandleRawConnection(wrappedConn, host, port, isSecure)
			if !ok && err != nil {
				wrappedConn.Close()
				log.Error().Err(err).Msgf("failure to handle incoming connection for %s:%d", host, port)
			} else if ok {
				if err != nil {
					log.Panic().Err(err).Msg("unexpected error occurred")
				}
			} else {
				break
			}
		} else {
			log.Warn().Msg("no registered connection handler connection will be intercepted")
			break
		}
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

func ReadClientHello(b *bufio.Reader) (*tls.ClientHelloInfo, error) {
	var hInfo tls.ClientHelloInfo

	err := tls.Server(ROConn{r: b}, &tls.Config{
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			hInfo = *chi
			return nil, nil
		},
	}).HandshakeContext(context.Background())

	// If hInfo's Conn field is nil, then GetConfigForClient was never called, so another error occurred
	if hInfo.Conn == nil {
		return nil, err
	}

	return &hInfo, nil
}

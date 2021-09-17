package server

import (
	"bufio"
	"context"
	"crypto/tls"
)

func ReadClientHello(b *bufio.Reader) (*tls.ClientHelloInfo, error) {
	var hInfo tls.ClientHelloInfo

	// Use an ROConn so we can use the standard GOLang tls libraries to read
	// clientInfo during the handshake, but prevent the handshake completing.
	// This way we can use the clientInfo for our own uses, but keep the
	// majority of the connection "untouched" (resetable at least)
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

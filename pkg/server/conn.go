package server

// from: https://stackoverflow.com/questions/26196813/peek-into-conn-without-reading-in-go

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"time"

	"golang.org/x/xerrors"
)

type CloseWriter interface {
	CloseWrite() error
}

type PeekableConn struct {
	r        *bufio.Reader
	net.Conn // So that most methods are embedded
}

type MultiReaderConn struct {
	r        io.Reader
	net.Conn // So that most methods are embedded
}

func NewPeekableConn(c net.Conn) PeekableConn {
	return PeekableConn{
		r:    bufio.NewReader(c),
		Conn: c,
	}
}

func NewPeekableConnSize(c net.Conn, n int) PeekableConn {
	return PeekableConn{
		r:    bufio.NewReaderSize(c, n),
		Conn: c,
	}
}

func (b PeekableConn) Peek(n int) ([]byte, error) {
	return b.r.Peek(n)
}

func (b PeekableConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func (b PeekableConn) CloseWrite() error {
	return b.Conn.(CloseWriter).CloseWrite()
}

// NewMultiReaderConn puts multiple readers before the connection reader
// This means that the all the readers need to be exahusted before the connection
// reader will be read.
func NewMultiReaderConn(c net.Conn, readers ...io.Reader) MultiReaderConn {
	readers = append(readers, c)
	return MultiReaderConn{
		r:    io.MultiReader(readers...),
		Conn: c,
	}
}

func (mr MultiReaderConn) Read(p []byte) (int, error) {
	return mr.r.Read(p)
}

func (mr MultiReaderConn) CloseWrite() error {
	return mr.Conn.(CloseWriter).CloseWrite()
}

// ROConn is a readonly net.Conn interface implementation
// It provides the ability to read from the connection, but will return
// a connection closed "error" on a write attempt.
type ROConn struct {
	r *bufio.Reader
}

func (conn ROConn) Read(p []byte) (int, error)         { return conn.r.Read(p) }
func (conn ROConn) Write(p []byte) (int, error)        { return 0, io.ErrClosedPipe }
func (conn ROConn) Close() error                       { return nil }
func (conn ROConn) LocalAddr() net.Addr                { return nil }
func (conn ROConn) RemoteAddr() net.Addr               { return nil }
func (conn ROConn) SetDeadline(t time.Time) error      { return nil }
func (conn ROConn) SetReadDeadline(t time.Time) error  { return nil }
func (conn ROConn) SetWriteDeadline(t time.Time) error { return nil }

// connLooksLikeHTTP reports whether a buffer might contain a plaintext HTTP request.
func connLooksLikeHTTP(buf []byte) bool {
	switch string(buf[:5]) {
	case "GET /", "HEAD ", "POST ", "PUT /", "OPTIO", "PROPF", "CONNE":
		return true
	}
	return false
}

func upgradeConnection(conn net.Conn, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) (net.Conn, error) {
	config := &tls.Config{
		InsecureSkipVerify: true,
		GetCertificate:     getCertificate,
	}

	tlsServer := tls.Server(conn, config)
	if err := tlsServer.Handshake(); err != nil {
		err = xerrors.Errorf("tls server %s handshake with client %s failed: %w", conn.LocalAddr().String(), conn.RemoteAddr().String(), err)
		return nil, err
	}

	return tlsServer, nil
}

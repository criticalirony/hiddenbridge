package server

// from: https://stackoverflow.com/questions/26196813/peek-into-conn-without-reading-in-go

import (
	"bufio"
	"io"
	"net"
	"time"
)

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

func NewBufferedConnSize(c net.Conn, n int) PeekableConn {
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

// connLooksLikeHTTP reports whether a buffer might containt a plaintext HTTP request.
func connLooksLikeHTTP(buf []byte) bool {
	switch string(buf[:5]) {
	case "GET /", "HEAD ", "POST ", "PUT /", "OPTIO":
		return true
	}
	return false
}

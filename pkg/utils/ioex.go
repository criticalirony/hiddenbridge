package utils

import "io"

type teeCloser struct {
	r io.Reader
	c io.Closer
}

func TeeCloser(r io.ReadCloser, w io.Writer) io.ReadCloser {
	return &teeCloser{io.TeeReader(r, w), r}
}

func (t teeCloser) Close() error {
	return t.c.Close()
}

func (t teeCloser) Read(p []byte) (n int, err error) {
	return t.r.Read(p)
}

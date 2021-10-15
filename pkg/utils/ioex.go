package utils

import (
	"bytes"
	"io"

	"github.com/rs/zerolog/log"
)

type teeCloser struct {
	r io.Reader
	c io.Closer
}

func TeeCloser(r io.Reader, w io.Writer) io.ReadCloser {
	tc := &teeCloser{}
	tc.r = io.TeeReader(r, w)

	if rc, ok := r.(io.Closer); ok {
		tc.c = rc
	} else {
		tc.c = io.NopCloser(r)
	}

	return tc
}

func (t teeCloser) Close() error {
	return t.c.Close()
}

func (t teeCloser) Read(p []byte) (n int, err error) {
	return t.r.Read(p)
}

type multiCloser struct {
	r io.Reader
	c []io.Closer
}

func MultiCloser(readers ...io.Reader) io.ReadCloser {
	mc := &multiCloser{}
	mc.r = io.MultiReader(readers...)

	for _, r := range readers {
		if rc, ok := r.(io.Closer); ok {
			mc.c = append(mc.c, rc)
		}
	}

	return mc
}

func (mc *multiCloser) Read(p []byte) (n int, err error) {
	return mc.r.Read(p)
}

func (mc *multiCloser) Close() error {
	for _, c := range mc.c {
		if err := c.Close(); err != nil {
			log.Error().Err(err).Msg("multicloser failed to close io.ReadCloser")
		}
	}

	return nil
}

type Resetter interface {
	Reset()
}

type ReReadCloser interface {
	io.Reader
	io.Closer
	Resetter
}

type reReadCloser struct {
	writeBuf        *bytes.Buffer
	readBuf         *bytes.Buffer
	reader          io.Reader
	compositeReader io.Reader
	closer          io.Closer
}

func NewReReadCloser(reader io.ReadCloser) ReReadCloser {
	writeBuf := &bytes.Buffer{}

	rrc := &reReadCloser{
		writeBuf:        writeBuf,
		readBuf:         &bytes.Buffer{},
		reader:          reader,
		compositeReader: io.TeeReader(reader, writeBuf),
	}

	if c, ok := reader.(io.Closer); ok {
		rrc.closer = c
	} else {
		rrc.closer = io.NopCloser(reader)
	}

	return rrc
}

func (r *reReadCloser) Read(p []byte) (n int, err error) {
	n, err = r.compositeReader.Read(p)
	return n, err
}

func (r *reReadCloser) Close() error {
	return r.closer.Close()
}

func (r *reReadCloser) Reset() {
	readBuf := &bytes.Buffer{}
	readBuf.Write(r.writeBuf.Bytes())
	readBuf.Write(r.readBuf.Bytes())
	r.writeBuf.Reset()
	r.readBuf = readBuf
	r.compositeReader = io.TeeReader(io.MultiReader(r.readBuf, r.reader), r.writeBuf)
}

package server

import (
	"bytes"
	"errors"
	"fmt"
	"hiddenbridge/pkg/utils"
	"io"
	"io/ioutil"
	"net/http"
	"net/textproto"
	"strconv"

	"github.com/rs/zerolog/log"
	"golang.org/x/xerrors"
)

type ResponseModifier struct {
	Body            *bytes.Buffer
	origRespBodyBuf *bytes.Buffer

	Resp        *http.Response
	initialized bool
	wroteHeader bool
	written     int
}

func NewResponseModifier(resp *http.Response) *ResponseModifier {
	if resp == nil {
		resp = &http.Response{}
	}

	origRespBodyBuf := &bytes.Buffer{}
	resp.Body = utils.TeeCloser(resp.Body, origRespBodyBuf)

	if len(resp.Proto) == 0 || resp.ProtoMajor == 0 {
		resp.Proto = "HTTP/1.1"
		resp.ProtoMajor = 1
		resp.ProtoMinor = 1
	}

	r := &ResponseModifier{
		Resp:            resp,
		written:         -1,
		initialized:     true, // So we know if NewResponseModifer was called or not
		Body:            &bytes.Buffer{},
		origRespBodyBuf: origRespBodyBuf,
	}

	return r
}

func (rm *ResponseModifier) Header() http.Header {
	m := rm.Resp.Header
	if m == nil {
		m = http.Header{}
		rm.Resp.Header = m
	}
	return m
}

func (rm *ResponseModifier) writeHeader(b []byte, str string) {
	if rm.wroteHeader {
		return
	}

	m := rm.Header()

	_, hasType := m["Content-Type"]
	hasNoTE := m.Get("Transfer-Encoding") == "" // missing (nil) or string (len > 0) means it has/needs a transfer encoding
	if !hasType && hasNoTE {
		if b == nil {
			if len(str) > 512 {
				str = str[:512]
			}
			b = []byte(str)
		}

		m.Set("Content-Type", http.DetectContentType(b))
	}

	rm.WriteHeader(200)
}

func (rm *ResponseModifier) Write(data []byte) (int, error) {
	rm.writeHeader(data, "")
	if rm.Body != nil {
		rm.Body.Write(data)
	}

	if rm.written < 0 {
		rm.written = 0
	}
	rm.written += len(data)

	return len(data), nil
}

func (rm *ResponseModifier) WriteString(str string) (int, error) {
	rm.writeHeader(nil, str)
	if rm.Body != nil {
		rm.Body.WriteString(str)
	}

	if rm.written < 0 {
		rm.written = 0
	}
	rm.written += len(str)

	return len(str), nil
}

func checkWriteHeaderCode(code int) {
	if code < 100 || code > 999 {
		log.Panic().Int("code", code).Msg("invalid WriteHeader code")
	}
}

func (rm *ResponseModifier) WriteHeader(code int) {
	if rm.wroteHeader {
		return
	}

	checkWriteHeaderCode(code)
	rm.Resp.StatusCode = code
	rm.wroteHeader = true
	if rm.Resp.Header == nil {
		rm.Resp.Header = http.Header{}
	}
}

func (rm *ResponseModifier) Flush() {
	if !rm.wroteHeader {
		rm.WriteHeader(rm.Resp.StatusCode)
	}
}

func parseContentLength(cl string) int64 {
	cl = textproto.TrimString(cl)
	if cl == "" {
		return -1
	}
	n, err := strconv.ParseUint(cl, 10, 63)
	if err != nil {
		return -1
	}
	return int64(n)
}

func (rm *ResponseModifier) Result() (*http.Response, error) {
	if rm.Resp == nil {
		return nil, xerrors.Errorf("no response result available")
	}

	res := rm.Resp

	if res.StatusCode == 0 {
		res.StatusCode = http.StatusOK
	}

	rm.Flush()

	res.Status = fmt.Sprintf("%03d %s", res.StatusCode, http.StatusText(res.StatusCode))

	if res.Body != nil {
		// If nothing has been written yet as the response body, write the original response body to the result
		if !rm.initialized || rm.written < 0 {
			if _, err := utils.CopyBuffer(rm.Body, rm.origRespBodyBuf, nil); err != nil {
				return nil, xerrors.Errorf("failed to copy original response buffer: %w", err)
			}

			if _, err := res.Body.Read(nil); err == nil {
				if _, err := utils.CopyBuffer(rm.Body, res.Body, nil); err != nil {
					return nil, xerrors.Errorf("failed to copy original response buffer: %w", err)
				}
			} else if !errors.Is(err, io.EOF) && err.Error() != "http: read on closed response body" {
				return nil, xerrors.Errorf("unexpected error reading response body: %w", err)
			}
		}

		if _, ok := res.Body.(io.Closer); ok {
			res.Body.Close()
		}
	}

	if rm.Body != nil {
		res.Body = ioutil.NopCloser(bytes.NewReader(rm.Body.Bytes()))
	} else {
		res.Body = http.NoBody
	}

	res.ContentLength = parseContentLength(res.Header.Get("Content-Length"))

	// Not supporting trailers - headers after body

	return res, nil
}

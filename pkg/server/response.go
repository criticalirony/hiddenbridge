package server

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"strconv"

	"github.com/rs/zerolog/log"
)

type ResponseModifier struct {
	Body *bytes.Buffer

	resp        *http.Response
	wroteHeader bool
}

func NewResponseModifier(resp *http.Response) *ResponseModifier {
	if resp == nil {
		resp = &http.Response{}
	}

	if len(resp.Proto) == 0 || resp.ProtoMajor == 0 {
		resp.Proto = "HTTP/1.1"
		resp.ProtoMajor = 1
		resp.ProtoMinor = 1
	}

	r := &ResponseModifier{
		resp: resp,
		Body: &bytes.Buffer{},
	}

	return r
}

func (rm *ResponseModifier) Header() http.Header {
	m := rm.resp.Header
	if m == nil {
		m = http.Header{}
		rm.resp.Header = m
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

	return len(data), nil
}

func (rm *ResponseModifier) WriteString(str string) (int, error) {
	rm.writeHeader(nil, str)
	if rm.Body != nil {
		rm.Body.WriteString(str)
	}
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
	rm.resp.StatusCode = code
	rm.wroteHeader = true
	if rm.resp.Header == nil {
		rm.resp.Header = http.Header{}
	}
}

func (rm *ResponseModifier) Flush() {
	if !rm.wroteHeader {
		rm.WriteHeader(200)
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

func (rm *ResponseModifier) Result() *http.Response {
	if rm.resp == nil {
		return nil
	}

	res := rm.resp

	if res.StatusCode == 0 {
		res.StatusCode = http.StatusOK
	}

	res.Status = fmt.Sprintf("%03d %s", res.StatusCode, http.StatusText(res.StatusCode))

	if res.Body != nil {
		if _, ok := res.Body.(io.Closer); ok {
			res.Body.Close()
		}
	}

	if rm.Body != nil {
		res.Body = io.NopCloser(bytes.NewReader(rm.Body.Bytes()))
	} else {
		res.Body = http.NoBody
	}

	res.ContentLength = parseContentLength(res.Header.Get("Content-Length"))

	// Not supporting trailers - headers after body

	return res
}

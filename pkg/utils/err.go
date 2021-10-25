package utils

type HTTPError struct {
	ErrorString string
	StatusCode  int
}

func (he *HTTPError) Error() string { return he.ErrorString }
func (he *HTTPError) Status() int   { return he.StatusCode }

var (
	// ErrHTTPNotFound is returned when a http uri can not be found
	ErrHTTPNotFound = &HTTPError{"not found", 404}

	// ErrHTTPInternalServer is returned when an internal error occurs
	ErrHTTPInternalServer = &HTTPError{"internal server error", 500}
)

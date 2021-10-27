package request

type contextKey int

const (
	ReqContextKey contextKey = iota
)

type RequestContext map[string]interface{}

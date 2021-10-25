package utils

import "fmt"

// StringList flattens its arguments into a single []string.
// Each argument in args must have type string or []string.
// heavily copied from: go/src/cmd/internal/str/str.go
func StringList(args ...interface{}) []string {
	var x []string
	for _, arg := range args {
		switch arg := arg.(type) {
		case []string:
			x = append(x, arg...)
		case string:
			x = append(x, arg)
		default:
			panic("stringList: invalid argument of type " + fmt.Sprintf("%T", arg))
		}
	}
	return x
}

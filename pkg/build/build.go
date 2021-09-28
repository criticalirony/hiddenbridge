package build

import "fmt"

// Blatently copied from: https://github.com/gomods/athens/blob/main/pkg/build/build.go

// Details represents known data for a given build
type Details struct {
	Version string `json:"version,omitempty"`
	Date    string `json:"date,omitempty"`
}

var version, buildDate string

// String returns build details as a string with formatting
// suitable for console output.
func String() string {
	return fmt.Sprintf("Build Details:\n\tVersion:\t%s\n\tDate:\t\t%s", version, buildDate)
}

// Data returns build details as a struct
func Data() Details {
	return Details{
		Version: version,
		Date:    buildDate,
	}
}

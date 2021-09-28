package utils

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeURL(t *testing.T) {
	var input_data = []string{
		"192.168.1.1",
		"192.168.1.1:80",
		"192.168.1.1:443",
		"http://192.168.1.1",
		"https://192.168.1.1",
		"http://192.168.1.1:80",
		"http://192.168.1.1:8080",
		"https://192.168.1.1:443",
		"http://192.168.1.1:8443",
		"bob.com",
		"bob.com:80",
		"bob.com:443",
		"bob.com:7878",
		"http://bob.com",
		"http://bom.com:7878",
		"https://bob.com",
		"https://bob.com:9090",
	}

	var expected_data = []string{
		"http://192.168.1.1:80",
		"http://192.168.1.1:80",
		"https://192.168.1.1:443",
		"http://192.168.1.1:80",
		"https://192.168.1.1:443",
		"http://192.168.1.1:80",
		"http://192.168.1.1:8080",
		"https://192.168.1.1:443",
		"http://192.168.1.1:8443",
		"http://bob.com:80",
		"http://bob.com:80",
		"https://bob.com:443",
		"http://bob.com:7878",
		"http://bob.com:80",
		"http://bom.com:7878",
		"https://bob.com:443",
		"https://bob.com:9090",
	}

	for i, data := range input_data {
		u, err := NormalizeURL(data)
		require.Nil(t, err)
		require.Equal(t, expected_data[i], u.String(), "Input: %s", data)
	}
}

func TestNormalizeURLWithPaths(t *testing.T) {
	var input_data = []string{
		"192.168.1.1/path/to/somewhere",
		"192.168.1.1/",

		"192.168.1.1:80/path/to/somewhere",
		"192.168.1.1:80/",

		"192.168.1.1:443/path/to/somewhere",
		"192.168.1.1:443/",

		"http://192.168.1.1/path/to/somewhere",
		"http://192.168.1.1/",

		"https://192.168.1.1/path/to/somewhere",
		"https://192.168.1.1/",

		"http://192.168.1.1:80/path/to/somewhere",
		"http://192.168.1.1:80/",

		"http://192.168.1.1:8080/path/to/somewhere",
		"http://192.168.1.1:8080/",

		"https://192.168.1.1:443/path/to/somewhere",
		"https://192.168.1.1:443/",

		"http://192.168.1.1:8443/path/to/somewhere",
		"http://192.168.1.1:8443/",

		"bob.com/path/to/somewhere",
		"bob.com/",

		"bob.com:80/path/to/somewhere",
		"bob.com:80/",

		"bob.com:443/path/to/somewhere",
		"bob.com:443/",

		"bob.com:7878/path/to/somewhere",
		"bob.com:7878/",

		"http://bob.com/path/to/somewhere",
		"http://bob.com/",

		"http://bom.com:7878/path/to/somewhere",
		"http://bom.com:7878/",

		"https://bob.com/path/to/somewhere",
		"https://bob.com/",

		"https://bob.com:9090/path/to/somewhere",
		"https://bob.com:9090/",
	}

	var expected_data = []string{
		"http://192.168.1.1:80/path/to/somewhere",
		"http://192.168.1.1:80/",

		"http://192.168.1.1:80/path/to/somewhere",
		"http://192.168.1.1:80/",

		"https://192.168.1.1:443/path/to/somewhere",
		"https://192.168.1.1:443/",

		"http://192.168.1.1:80/path/to/somewhere",
		"http://192.168.1.1:80/",

		"https://192.168.1.1:443/path/to/somewhere",
		"https://192.168.1.1:443/",

		"http://192.168.1.1:80/path/to/somewhere",
		"http://192.168.1.1:80/",

		"http://192.168.1.1:8080/path/to/somewhere",
		"http://192.168.1.1:8080/",

		"https://192.168.1.1:443/path/to/somewhere",
		"https://192.168.1.1:443/",

		"http://192.168.1.1:8443/path/to/somewhere",
		"http://192.168.1.1:8443/",

		"http://bob.com:80/path/to/somewhere",
		"http://bob.com:80/",

		"http://bob.com:80/path/to/somewhere",
		"http://bob.com:80/",

		"https://bob.com:443/path/to/somewhere",
		"https://bob.com:443/",

		"http://bob.com:7878/path/to/somewhere",
		"http://bob.com:7878/",

		"http://bob.com:80/path/to/somewhere",
		"http://bob.com:80/",

		"http://bom.com:7878/path/to/somewhere",
		"http://bom.com:7878/",

		"https://bob.com:443/path/to/somewhere",
		"https://bob.com:443/",

		"https://bob.com:9090/path/to/somewhere",
		"https://bob.com:9090/",
	}

	for i, data := range input_data {
		u, err := NormalizeURL(data)
		require.Nil(t, err, fmt.Sprintf("Test: %d Data: %s", i, data))
		require.Equal(t, expected_data[i], u.String(), "Test: %d Data: %s", i, data)
	}
}

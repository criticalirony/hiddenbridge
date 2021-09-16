package utils

import (
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

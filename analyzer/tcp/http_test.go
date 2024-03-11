package tcp

import (
	"reflect"
	"strings"
	"testing"

	"github.com/apernet/OpenGFW/analyzer"
)

func TestHTTPParsing_Request(t *testing.T) {
	testCases := map[string]analyzer.PropMap{
		"GET / HTTP/1.1\r\n": {
			"method": "GET", "path": "/", "version": "HTTP/1.1",
		},
		"POST /hello?a=1&b=2 HTTP/1.0\r\n": {
			"method": "POST", "path": "/hello?a=1&b=2", "version": "HTTP/1.0",
		},
		"PUT /world HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody": {
			"method": "PUT", "path": "/world", "version": "HTTP/1.1", "headers": analyzer.PropMap{"content-length": "4"},
		},
		"DELETE /goodbye HTTP/2.0\r\n": {
			"method": "DELETE", "path": "/goodbye", "version": "HTTP/2.0",
		},
	}

	for tc, want := range testCases {
		t.Run(strings.Split(tc, " ")[0], func(t *testing.T) {
			tc, want := tc, want
			t.Parallel()

			u, _ := newHTTPStream(nil).Feed(false, false, false, 0, []byte(tc))
			got := u.M.Get("req")
			if !reflect.DeepEqual(got, want) {
				t.Errorf("\"%s\" parsed = %v, want %v", tc, got, want)
			}
		})
	}
}

func TestHTTPParsing_Response(t *testing.T) {
	testCases := map[string]analyzer.PropMap{
		"HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nbody": {
			"version": "HTTP/1.0", "status": 200,
			"headers": analyzer.PropMap{"content-length": "4"},
		},
		"HTTP/2.0 204 No Content\r\n\r\n": {
			"version": "HTTP/2.0", "status": 204,
		},
	}

	for tc, want := range testCases {
		t.Run(strings.Split(tc, " ")[0], func(t *testing.T) {
			tc, want := tc, want
			t.Parallel()

			u, _ := newHTTPStream(nil).Feed(true, false, false, 0, []byte(tc))
			got := u.M.Get("resp")
			if !reflect.DeepEqual(got, want) {
				t.Errorf("\"%s\" parsed = %v, want %v", tc, got, want)
			}
		})
	}
}

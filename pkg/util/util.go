package util

import (
	"io"
	"io/ioutil"
	"net/http"
)

func Drain(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
		_, _ = io.Copy(ioutil.Discard, resp.Body)
	}
}

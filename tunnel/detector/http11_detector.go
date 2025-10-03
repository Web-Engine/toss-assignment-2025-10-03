package detector

import (
	"bytes"
	"context"
	"toss/tunnel"
)

type Http11Detector struct {
}

func NewHttp11Detector() *Http11Detector {
	return &Http11Detector{}
}

var httpMethods = [][]byte{
	[]byte("GET "),
	[]byte("POST "),
	[]byte("PUT "),
	[]byte("PATCH "),
	[]byte("DELETE "),
	[]byte("HEAD "),
	[]byte("OPTIONS "),
	[]byte("CONNECT "),
	[]byte("TRACE "),
}

func (detector Http11Detector) Detect(tun *tunnel.Tunnel, ctx context.Context) bool {
	peek, err := tun.Downstream.Reader.Peek(7)
	if err != nil {
		return false
	}

	for _, method := range httpMethods {
		if bytes.Equal(method, peek[:len(method)]) {
			return true
		}
	}

	return false
}

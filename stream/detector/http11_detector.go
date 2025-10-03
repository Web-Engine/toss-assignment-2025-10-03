package detector

import (
	"bytes"
	"context"
	"toss/stream"
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

func (detector Http11Detector) Detect(stream *stream.DuplexStream, ctx context.Context) bool {
	peek, err := stream.Client.Reader.Peek(7)
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

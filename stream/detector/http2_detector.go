package detector

import (
	"bytes"
	"context"
	"toss/stream"
)

type Http2Detector struct {
}

func NewHttp2Detector() *Http2Detector {
	return &Http2Detector{}
}

var http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

func (detector *Http2Detector) Detect(stream *stream.DuplexStream, ctx context.Context) bool {
	buffer, err := stream.Client.Reader.Peek(len(http2Preface))
	if err != nil {
		return false
	}

	return bytes.Equal(buffer, http2Preface)
}

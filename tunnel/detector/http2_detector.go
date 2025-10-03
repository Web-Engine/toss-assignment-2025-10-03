package detector

import (
	"bytes"
	"context"
	"toss/tunnel"
)

type Http2Detector struct {
}

func NewHttp2Detector() *Http2Detector {
	return &Http2Detector{}
}

var http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

func (detector *Http2Detector) Detect(tun *tunnel.Tunnel, ctx context.Context) bool {
	buffer, err := tun.Downstream.Reader.Peek(len(http2Preface))
	if err != nil {
		return false
	}

	return bytes.Equal(buffer, http2Preface)
}

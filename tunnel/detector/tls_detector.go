package detector

import (
	"bytes"
	"context"
	"toss/tunnel"
)

var clientHelloHeaderBytes = []byte{0x16, 0x03, 0x01}

type TlsDetector struct {
}

func NewTlsDetector() *TlsDetector {
	return &TlsDetector{}
}

func (detector *TlsDetector) Detect(tun *tunnel.Tunnel, ctx context.Context) bool {
	buffer, err := tun.Downstream.Reader.Peek(3)
	if err != nil {
		return false
	}

	return bytes.Equal(buffer, clientHelloHeaderBytes)
}

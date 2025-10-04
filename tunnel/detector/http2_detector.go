package detector

import (
	"bytes"
	"log/slog"
	"toss/tunnel"
	"toss/tunnel/handler"
)

type Http2Detector struct {
	logger *slog.Logger
}

func NewHttp2Detector(logger *slog.Logger) *Http2Detector {
	return &Http2Detector{
		logger: logger,
	}
}

var http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

func (d *Http2Detector) Detect(tun *tunnel.Tunnel) (tunnel.DetectResult, tunnel.Handler) {
	if tun.Downstream.Reader.Buffered() < len(http2Preface) {
		return tunnel.DetectResultPossible, nil
	}

	buffer, err := tun.Downstream.Reader.Peek(len(http2Preface))
	if err != nil {
		return tunnel.DetectResultNever, nil
	}

	if !bytes.Equal(buffer, http2Preface) {
		return tunnel.DetectResultNever, nil
	}

	return tunnel.DetectResultMatched, handler.NewHttp2Handler(d.logger)
}

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
	logger := d.logger.With("context", "Http11Detector")

	peek, err := tun.Downstream.Reader.Peek(len(http2Preface))
	if err != nil {
		logger.Debug("http2 protocol: possible: failed to peek (peek maybe not ready)")
		return tunnel.DetectResultNever, nil
	}

	if !bytes.Equal(peek, http2Preface) {
		logger.Debug("http2 protocol: never", "peek", string(peek))
		return tunnel.DetectResultNever, nil
	}

	logger.Debug("http2 protocol: matched")
	return tunnel.DetectResultMatched, handler.NewHttp2Handler(d.logger)
}

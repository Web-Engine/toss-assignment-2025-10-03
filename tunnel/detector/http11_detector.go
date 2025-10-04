package detector

import (
	"bytes"
	"log/slog"
	"toss/tunnel"
	"toss/tunnel/handler"
)

type Http11Detector struct {
	logger *slog.Logger
}

func NewHttp11Detector(logger *slog.Logger) *Http11Detector {
	return &Http11Detector{
		logger: logger,
	}
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

func (d Http11Detector) Detect(tun *tunnel.Tunnel) (tunnel.DetectResult, tunnel.Handler) {
	logger := d.logger.With("context", "Http11Detector")

	peek, err := tun.Downstream.Reader.Peek(7)
	if err != nil {
		logger.Debug("http1.1 protocol: possible: failed to peek (buffer maybe not ready)")
		return tunnel.DetectResultPossible, nil
	}

	for _, method := range httpMethods {
		if bytes.Equal(method, peek[:len(method)]) {
			logger.Debug("http1.1 protocol: matched", "method", string(method))
			return tunnel.DetectResultMatched, handler.NewHttp11Handler(d.logger)
		}
	}
	logger.Debug("http1.1 protocol: never", "peek", string(peek))
	return tunnel.DetectResultNever, nil
}

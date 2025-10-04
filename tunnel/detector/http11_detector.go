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
	peek, err := tun.Downstream.Reader.Peek(7)
	if err != nil {
		return tunnel.DetectResultPossible, nil
	}

	for _, method := range httpMethods {
		if bytes.Equal(method, peek[:len(method)]) {
			return tunnel.DetectResultMatched, handler.NewHttp11Handler(d.logger)
		}
	}

	return tunnel.DetectResultNever, nil
}

package handler

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"toss/tunnel"
)

type Http11Handler struct {
	logger *slog.Logger
}

func NewHttp11Handler(logger *slog.Logger) *Http11Handler {
	return &Http11Handler{
		logger: logger,
	}
}

func (h *Http11Handler) Handle(tun *tunnel.Tunnel) error {
	var handler tunnel.Handler = nil

	logger := h.logger.With("context", "Http11Handler")

	for {
		req, err := http.ReadRequest(tun.Downstream.Reader)
		if err != nil {
			return err
		}

		var reqBodyPreview *bytes.Buffer
		req.Body, reqBodyPreview = tunnel.NewTeeReadCloser(req.Body, 128)

		if err = req.Write(tun.Upstream.Writer); err != nil {
			return err
		}
		if err = tun.Upstream.Writer.Flush(); err != nil {
			return err
		}

		slogReq := slog.Group("req",
			slog.Any("method", req.Method),
			slog.Any("host", req.Host),
			slog.Any("url", req.URL.String()),
			slog.Any("headers", req.Header),
			slog.Any("body", reqBodyPreview.String()),
		)

		logger.Info("http request", slogReq)

		res, err := http.ReadResponse(tun.Upstream.Reader, req)
		if err != nil {
			return err
		}

		var resBodyPreview *bytes.Buffer
		res.Body, resBodyPreview = tunnel.NewTeeReadCloser(res.Body, 128)

		if err = res.Write(tun.Downstream.Writer); err != nil {
			return err
		}

		if err = tun.Downstream.Writer.Flush(); err != nil {
			return err
		}

		slogRes := slog.Group("res",
			slog.Any("status", res.StatusCode),
			slog.Any("status_code", res.StatusCode),
			slog.Any("headers", res.Header),
			slog.Any("body", resBodyPreview.String()),
		)

		logger.Info("http response", slogReq, slogRes)

		connectionHeader := strings.ToLower(res.Header.Get("Connection"))
		upgradeHeader := strings.ToLower(res.Header.Get("Upgrade"))

		if res.StatusCode == 101 && connectionHeader == "upgrade" && upgradeHeader == "websocket" {
			logger.Info("websocket bypassed")
			handler = NewByPassHandler(h.logger)
			break
		}
	}

	if handler != nil {
		return handler.Handle(tun)
	}

	return nil
}

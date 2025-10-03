package handler

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"toss/tunnel"

	"golang.org/x/net/http2"
)

type Http2Handler struct {
	logger *slog.Logger
}

func NewHttp2Handler(logger *slog.Logger) *Http2Handler {
	return &Http2Handler{
		logger: logger,
	}
}

func (h *Http2Handler) Handle(tun *tunnel.Tunnel) error {
	logger := h.logger.With("context", "Http2Handler")

	downstreamH2Server := &http2.Server{}
	upstreamH2Transport := &http2.Transport{}
	upstreamH2Conn, err := upstreamH2Transport.NewClientConn(tun.Upstream.Conn)

	if err != nil {
		return err
	}

	h2Handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		outReq := req.Clone(req.Context())
		outReq.URL = &url.URL{
			Scheme:   "https",
			Host:     req.Host,
			Path:     req.URL.Path,
			RawQuery: req.URL.RawQuery,
		}
		outReq.RequestURI = ""

		var reqBodyPreview *bytes.Buffer
		outReq.Body, reqBodyPreview = tunnel.NewTeeReadCloser(outReq.Body, 128)

		res, err := upstreamH2Conn.RoundTrip(outReq)
		if err != nil {
			http.Error(w, "upstream roundtrip error: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer res.Body.Close()

		slogReq := slog.Group("req",
			slog.Any("method", req.Method),
			slog.Any("host", req.Host),
			slog.Any("url", req.URL.String()),
			slog.Any("headers", req.Header),
			slog.Any("body", reqBodyPreview.String()),
		)
		logger.Info("http request", slogReq)

		for k, vv := range res.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}

		w.WriteHeader(res.StatusCode)

		var resBodyPreview *bytes.Buffer
		res.Body, resBodyPreview = tunnel.NewTeeReadCloser(res.Body, 128)

		if _, err := io.Copy(w, res.Body); err != nil {
			_ = err
			return
		}

		slogRes := slog.Group("res",
			slog.Any("status", res.Status),
			slog.Any("status_code", res.StatusCode),
			slog.Any("headers", res.Header),
			slog.Any("body", resBodyPreview.String()),
		)

		logger.Info("http response", slogReq, slogRes)
	})

	downstreamH2ServerOpts := &http2.ServeConnOpts{
		Handler: h2Handler,
	}
	downstreamH2Server.ServeConn(tun.Downstream, downstreamH2ServerOpts)

	return nil
}

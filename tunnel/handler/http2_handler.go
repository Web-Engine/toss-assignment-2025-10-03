package handler

import (
	"io"
	"net/http"
	"net/url"
	"toss/tunnel"

	"golang.org/x/net/http2"
)

type Http2Handler struct {
}

func NewHttp2Handler() *Http2Handler {
	return &Http2Handler{}
}

func (h *Http2Handler) Handle(tun *tunnel.Tunnel) error {
	srv := &http2.Server{}

	// 1) 업스트림: 기존 TLS(h2) 연결 위에 http2 클라이언트 올리기
	tr := &http2.Transport{}
	cc, err := tr.NewClientConn(tun.Upstream.Conn)
	if err != nil {
		return err
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		outReq := req.Clone(req.Context())
		outReq.URL = &url.URL{
			Scheme:   "https",
			Host:     req.Host,
			Path:     req.URL.Path,
			RawQuery: req.URL.RawQuery,
		}
		outReq.RequestURI = ""

		res, err := cc.RoundTrip(outReq)
		if err != nil {
			http.Error(w, "upstream roundtrip error: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer res.Body.Close()

		for k, vv := range res.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}

		w.WriteHeader(res.StatusCode)

		if _, err := io.Copy(w, res.Body); err != nil {
			_ = err
			return
		}
	})

	opts := &http2.ServeConnOpts{
		Handler: handler,
	}
	srv.ServeConn(tun.Downstream, opts)

	return nil
}

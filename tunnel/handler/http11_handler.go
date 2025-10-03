package handler

import (
	"log"
	"net/http"
	"toss/tunnel"
)

type Http11Handler struct {
}

func NewHttp11Handler() *Http11Handler {
	return &Http11Handler{}
}

func (h *Http11Handler) Handle(tun *tunnel.Tunnel) error {
	for {
		req, err := http.ReadRequest(tun.Downstream.Reader)
		if err != nil {
			return err
		}

		log.Printf("Request Method: %v", req.Method)
		log.Printf("Request URL: %v", req.URL)
		log.Printf("Request Body: %v", req.Body)

		if err = req.Write(tun.Upstream.Writer); err != nil {
			return err
		}

		if err = tun.Upstream.Writer.Flush(); err != nil {
			return err
		}

		res, err := http.ReadResponse(tun.Upstream.Reader, req)
		if err != nil {
			return err
		}

		log.Printf("Response Status: %v", res.StatusCode)

		if err = res.Write(tun.Downstream.Writer); err != nil {
			return err
		}

		if err = tun.Downstream.Writer.Flush(); err != nil {
			return err
		}
	}
}

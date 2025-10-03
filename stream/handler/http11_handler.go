package handler

import (
	"log"
	"net/http"
	"toss/stream"
)

type Http11Handler struct {
}

func NewHttp11Handler() *Http11Handler {
	return &Http11Handler{}
}

func (h *Http11Handler) Handle(stream *stream.DuplexStream) error {
	for {
		req, err := http.ReadRequest(stream.Client.Reader)
		if err != nil {
			return err
		}

		log.Printf("Request Method: %v", req.Method)
		log.Printf("Request URL: %v", req.URL)
		log.Printf("Request Body: %v", req.Body)

		if err = req.Write(stream.Server.Writer); err != nil {
			return err
		}

		if err = stream.Server.Writer.Flush(); err != nil {
			return err
		}

		res, err := http.ReadResponse(stream.Server.Reader, req)
		if err != nil {
			return err
		}
		
		log.Printf("Response Status: %v", res.StatusCode)

		if err = res.Write(stream.Client.Writer); err != nil {
			return err
		}

		if err = stream.Client.Writer.Flush(); err != nil {
			return err
		}
	}
}

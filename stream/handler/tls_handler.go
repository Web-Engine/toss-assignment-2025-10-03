package handler

import (
	"toss/stream"
)

type TlsHandler struct {
}

func NewTlsHandler() *TlsHandler {
	return &TlsHandler{}
}

func (handler *TlsHandler) Handle(stream *stream.DuplexStream) error {
	//tlsConfig := &tls.Config{
	//	GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {},
	//	NextProtos:     []string{"h2", "http/1.1"},
	//}
	return nil
}

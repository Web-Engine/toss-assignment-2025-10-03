package handler

import (
	"crypto/tls"
	"errors"
	"toss/tunnel"
	"toss/tunnel/detector"
)

type TlsHandler struct {
	getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

func NewTlsHandler(getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *TlsHandler {
	return &TlsHandler{
		getCertificate: getCertificate,
	}
}

func (handler *TlsHandler) Handle(tun *tunnel.Tunnel) error {
	var clientHello *tls.ClientHelloInfo

	downstreamConfig := &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			clientHello = info

			return handler.getCertificate(info)
		},
	}

	downstreamTlsConn := tls.Server(tun.Downstream, downstreamConfig)
	if err := downstreamTlsConn.Handshake(); err != nil {
		return err
	}

	if clientHello == nil {
		return errors.New("ClientHello is nil")
	}

	upstreamConfig := &tls.Config{}
	if clientHello.ServerName != "" {
		upstreamConfig.ServerName = clientHello.ServerName
	}

	if len(clientHello.SupportedProtos) > 0 {
		upstreamConfig.NextProtos = clientHello.SupportedProtos
	}

	upstreamTlsConn := tls.Client(tun.Upstream, upstreamConfig)
	if err := upstreamTlsConn.Handshake(); err != nil {
		return err
	}

	protocols := []ProtocolHandler{
		{Detector: detector.NewHttp11Detector(), Handler: NewHttp11Handler()},
		{Detector: detector.NewHttp2Detector(), Handler: NewHttp2Handler()},
	}

	restHandler := NewClientFirstHandler(protocols)

	tlsTun := tunnel.NewTunnelFromConn(downstreamTlsConn, upstreamTlsConn)
	return restHandler.Handle(tlsTun)
}

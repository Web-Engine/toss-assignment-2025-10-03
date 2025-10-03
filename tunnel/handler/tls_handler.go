package handler

import (
	"crypto/tls"
	"fmt"
	"toss/tunnel"
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
	var (
		upstreamTlsConn    *tls.Conn
		upstreamNegotiated string
	)

	downstreamConfig := &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			cert, err := handler.getCertificate(info)
			if err != nil {
				return nil, err
			}

			upstreamConfig := &tls.Config{
				NextProtos: info.SupportedProtos,
			}

			if info.ServerName != "" {
				upstreamConfig.ServerName = info.ServerName
			}

			conn := tls.Client(tun.Upstream, upstreamConfig)
			if err := conn.Handshake(); err != nil {
				return nil, err
			}

			negotiated := conn.ConnectionState().NegotiatedProtocol

			upstreamTlsConn = conn
			upstreamNegotiated = negotiated

			cfg := &tls.Config{
				Certificates: []tls.Certificate{*cert},
			}
			if negotiated != "" {
				cfg.NextProtos = []string{negotiated}
			}

			return cfg, nil
		},
	}

	downstreamTlsConn := tls.Server(tun.Downstream, downstreamConfig)
	if err := downstreamTlsConn.Handshake(); err != nil {
		return err
	}

	downstreamNegotiated := downstreamTlsConn.ConnectionState().NegotiatedProtocol

	if downstreamNegotiated != upstreamNegotiated {
		return fmt.Errorf("ALPN mismatch: downstream=%s upstream=%s", downstreamNegotiated, upstreamNegotiated)
	}

	var streamHandler tunnel.Handler
	switch downstreamNegotiated {
	case "h2":
		streamHandler = NewHttp2Handler()
	case "http/1.1":
		streamHandler = NewHttp11Handler()
	default:
		streamHandler = NewPipeHandler()
	}

	tlsTun := tunnel.NewTunnelFromConn(downstreamTlsConn, upstreamTlsConn)
	return streamHandler.Handle(tlsTun)
}

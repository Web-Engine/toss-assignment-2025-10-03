package handler

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"toss/cert"
	"toss/tunnel"
)

type TlsHandler struct {
	logger      *slog.Logger
	certManager *cert.Manager
}

func NewTlsHandler(logger *slog.Logger, certManager *cert.Manager) *TlsHandler {
	return &TlsHandler{
		logger:      logger,
		certManager: certManager,
	}
}

func (h *TlsHandler) Handle(tun *tunnel.Tunnel) error {
	logger := h.logger.With("context", "TlsHandler")

	var (
		upstreamTlsConn    *tls.Conn
		upstreamNegotiated string
	)

	logger.Debug("start tls handshake")

	downstreamConfig := &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			crt, err := h.certManager.GetCertificate(info)
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
			logger.Debug("upstream negotiated", "negotiated", negotiated)

			upstreamTlsConn = conn
			upstreamNegotiated = negotiated

			cfg := &tls.Config{
				Certificates: []tls.Certificate{*crt},
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
	logger.Debug("downstream negotiated", "negotiated", downstreamNegotiated)

	if downstreamNegotiated != upstreamNegotiated {
		return fmt.Errorf("ALPN mismatch: downstream=%s upstream=%s", downstreamNegotiated, upstreamNegotiated)
	}

	var streamHandler tunnel.Handler
	switch downstreamNegotiated {
	case "h2":
		streamHandler = NewHttp2Handler(h.logger)
	case "http/1.1":
		streamHandler = NewHttp11Handler(h.logger)
	default:
		streamHandler = NewByPassHandler(h.logger)
	}

	tlsTun := tunnel.NewTunnelFromConn(downstreamTlsConn, upstreamTlsConn)
	return streamHandler.Handle(tlsTun)
}

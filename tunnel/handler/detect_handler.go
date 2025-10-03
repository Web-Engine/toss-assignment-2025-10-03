package handler

import (
	"context"
	"log/slog"
	"time"
	"toss/tunnel"
)

type ProtocolSpecification struct {
	Detector tunnel.Detector
	Handler  tunnel.Handler
}

type DetectHandler struct {
	logger *slog.Logger
	specs  []ProtocolSpecification
}

func NewDetectHandler(logger *slog.Logger, specs []ProtocolSpecification) *DetectHandler {
	return &DetectHandler{
		logger: logger,
		specs:  specs,
	}
}

func (h DetectHandler) Handle(tun *tunnel.Tunnel) error {
	var streamHandler tunnel.Handler

	if err := tun.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		return err
	}

	for _, protocol := range h.specs {
		if protocol.Detector.Detect(tun, context.Background()) {
			streamHandler = protocol.Handler
		}
	}

	if err := tun.SetReadDeadline(time.Time{}); err != nil {
		return err
	}

	if streamHandler == nil {
		streamHandler = NewByPassHandler(h.logger)
	}

	return streamHandler.Handle(tun)
}

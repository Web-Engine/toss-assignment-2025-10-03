package handler

import (
	"log/slog"
	"time"
	"toss/tunnel"
)

type ProtocolSpecification struct {
	Detector tunnel.Detector
	Handler  tunnel.Handler
}

type DetectHandler struct {
	logger    *slog.Logger
	detectors []tunnel.Detector
}

func NewDetectHandler(logger *slog.Logger, detectors []tunnel.Detector) *DetectHandler {
	return &DetectHandler{
		logger:    logger,
		detectors: detectors,
	}
}

func (h DetectHandler) Handle(tun *tunnel.Tunnel) error {
	var streamHandler tunnel.Handler = nil

	if err := tun.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		return err
	}

	for _, detector := range h.detectors {
		if isDetected, handler := detector.Detect(tun); isDetected {
			streamHandler = handler
			break
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

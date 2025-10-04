package handler

import (
	"io"
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

	for {
		if err := tun.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil && err != io.EOF {
			slog.Error("error set read deadline", "error", err)
			return err
		}

		resultFlag := tunnel.DetectResultNever

		for _, detector := range h.detectors {
			result, handler := detector.Detect(tun)
			resultFlag |= result

			if result == tunnel.DetectResultMatched {
				streamHandler = handler
				break
			}
		}

		if err := tun.SetReadDeadline(time.Time{}); err != nil && err != io.EOF {
			slog.Error("error unset read deadline", "error", err)
			return err
		}

		if resultFlag == tunnel.DetectResultNever {
			break
		}

		if tun.Downstream.Reader.Buffered()+tun.Upstream.Reader.Buffered() > 128 {
			break
		}
	}

	if streamHandler == nil {
		streamHandler = NewByPassHandler(h.logger)
	}

	return streamHandler.Handle(tun)
}

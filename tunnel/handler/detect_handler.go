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

	if err := tun.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil && err != io.EOF {
		h.logger.Error("error set read deadline", "error", err)
		return err
	}

	for {
		h.logger.Debug("try to detect protocol")

		resultFlag := tunnel.DetectResultNever

		for _, detector := range h.detectors {
			result, handler := detector.Detect(tun)
			resultFlag |= result

			if result == tunnel.DetectResultMatched {
				streamHandler = handler
				break
			}
		}

		if streamHandler != nil {
			break
		}

		if resultFlag == tunnel.DetectResultNever {
			break
		}

		if tun.Downstream.Reader.Buffered()+tun.Upstream.Reader.Buffered() > 128 {
			h.logger.Debug("failed to detect protocol", "downstream.buffered", tun.Downstream.Reader.Buffered(), "upstream.buffered", tun.Upstream.Reader.Buffered())
			break
		}
	}

	if err := tun.SetReadDeadline(time.Time{}); err != nil && err != io.EOF {
		h.logger.Error("error unset read deadline", "error", err)
		return err
	}

	if streamHandler == nil {
		h.logger.Debug("no handler: fallback to bypass")
		streamHandler = NewByPassHandler(h.logger)
	}

	return streamHandler.Handle(tun)
}

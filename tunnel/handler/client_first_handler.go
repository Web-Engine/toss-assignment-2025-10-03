package handler

import (
	"context"
	"time"
	"toss/tunnel"
)

type ProtocolHandler struct {
	Detector tunnel.Detector
	Handler  tunnel.Handler
}

type ClientFirstHandler struct {
	protocols []ProtocolHandler
}

func NewClientFirstHandler(protocols []ProtocolHandler) *ClientFirstHandler {
	return &ClientFirstHandler{
		protocols: protocols,
	}
}

func (c ClientFirstHandler) Handle(tun *tunnel.Tunnel) error {
	var streamHandler tunnel.Handler

	if err := tun.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		return err
	}

	for _, protocol := range c.protocols {
		if protocol.Detector.Detect(tun, context.Background()) {
			streamHandler = protocol.Handler
		}
	}

	if err := tun.SetReadDeadline(time.Time{}); err != nil {
		return err
	}

	if streamHandler == nil {
		streamHandler = NewByPassHandler()
	}

	return streamHandler.Handle(tun)
}

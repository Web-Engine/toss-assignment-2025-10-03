package detector

import (
	"context"
	"time"
	"toss/tunnel"
)

type DownstreamPacketDetector struct {
}

func NewDownstreamPacketDetector() *DownstreamPacketDetector {
	return &DownstreamPacketDetector{}
}

func (d *DownstreamPacketDetector) Detect(tun *tunnel.Tunnel, ctx context.Context) bool {

	if err := tun.Downstream.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		return false
	}
	defer tun.Downstream.SetReadDeadline(time.Time{})

	if _, err := tun.Downstream.Reader.Peek(1); err != nil {
		return false
	}

	return true
}

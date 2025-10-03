package detector

import (
	"context"
	"time"
	"toss/tunnel"
)

type UpstreamPacketDetector struct {
}

func NewUpstreamPacketDetector() *UpstreamPacketDetector {
	return &UpstreamPacketDetector{}
}

func (d *UpstreamPacketDetector) Detect(tun *tunnel.Tunnel, ctx context.Context) bool {
	if err := tun.Upstream.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		return false
	}
	defer tun.Upstream.SetReadDeadline(time.Time{})

	if _, err := tun.Upstream.Reader.Peek(1); err != nil {
		return false
	}

	return true
}

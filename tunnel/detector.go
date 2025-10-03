package tunnel

import "context"

type Detector interface {
	Detect(tun *Tunnel, ctx context.Context) bool
}

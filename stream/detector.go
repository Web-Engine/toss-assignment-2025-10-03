package stream

import "context"

type Detector interface {
	Detect(stream *DuplexStream, ctx context.Context) bool
}

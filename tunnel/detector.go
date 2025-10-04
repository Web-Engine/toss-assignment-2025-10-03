package tunnel

type Detector interface {
	Detect(tun *Tunnel) (DetectResult, Handler)
}

type DetectResult uint8

const (
	DetectResultNever    = DetectResult(0)
	DetectResultPossible = DetectResult(1 << 0)
	DetectResultMatched  = DetectResult(1 << 1)
)

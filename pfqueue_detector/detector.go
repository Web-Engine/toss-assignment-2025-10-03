package pfqueue_detector

import "bytes"

const (
	UNDETECTED = 0

	BYPASS = 1
	TPROXY = 2
)

type Detector struct {
}

func NewDetector() *Detector {
	return &Detector{}
}

func (d *Detector) Analyze(buffer bytes.Buffer) uint32 {
	return BYPASS
}

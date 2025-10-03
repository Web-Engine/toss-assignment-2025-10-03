package tunnel

type Detector interface {
	Detect(tun *Tunnel) (bool, Handler)
}

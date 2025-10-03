package tunnel

type Handler interface {
	Handle(tun *Tunnel) error
}

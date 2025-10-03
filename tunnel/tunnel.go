package tunnel

import (
	"errors"
	"net"
	"time"
)

type Tunnel struct {
	Downstream *Stream
	Upstream   *Stream
}

func NewTunnel(downstream, upstream *Stream) *Tunnel {
	return &Tunnel{
		Downstream: downstream,
		Upstream:   upstream,
	}
}
func NewTunnelFromConn(downstream, upstream net.Conn) *Tunnel {
	return &Tunnel{
		Downstream: NewStream(downstream),
		Upstream:   NewStream(upstream),
	}
}

func (tun *Tunnel) SetReadDeadline(deadline time.Time) error {
	err1 := tun.Downstream.Conn.SetReadDeadline(deadline)
	err2 := tun.Upstream.Conn.SetReadDeadline(deadline)

	return errors.Join(err1, err2)
}

func (tun *Tunnel) Close() error {
	err1 := tun.Downstream.Conn.SetDeadline(time.Time{})
	err2 := tun.Upstream.Conn.SetDeadline(time.Time{})

	err3 := tun.Downstream.Conn.Close()
	err4 := tun.Upstream.Conn.Close()

	return errors.Join(err1, err2, err3, err4)
}

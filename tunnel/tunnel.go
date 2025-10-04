package tunnel

import (
	"errors"
	"net"
	"time"

	"github.com/google/uuid"
)

type Tunnel struct {
	Src net.Addr
	Dst net.Addr

	Downstream *Stream
	Upstream   *Stream

	id string
}

func NewTunnel(src, dst net.Addr, downstream, upstream *Stream) *Tunnel {
	return &Tunnel{
		Src: src,
		Dst: dst,

		Downstream: downstream,
		Upstream:   upstream,

		id: uuid.NewString(),
	}
}
func NewTunnelFromConn(src, dst net.Addr, downstream, upstream net.Conn) *Tunnel {
	return &Tunnel{
		Src: src,
		Dst: dst,
		
		Downstream: NewStream(downstream),
		Upstream:   NewStream(upstream),

		id: uuid.NewString(),
	}
}

func (tun *Tunnel) ID() string {
	return tun.id
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

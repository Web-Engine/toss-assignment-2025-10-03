package stream

import (
	"errors"
	"net"
	"time"
)

type DuplexStream struct {
	Client *Stream
	Server *Stream
}

func NewDuplexStream(client, server *Stream) *DuplexStream {
	return &DuplexStream{
		Client: client,
		Server: server,
	}
}
func NewDuplexStreamFromConn(client, server *net.TCPConn) *DuplexStream {
	return &DuplexStream{
		Client: NewStream(client),
		Server: NewStream(server),
	}
}

func (stream *DuplexStream) SetReadDeadline(deadline time.Time) error {
	err1 := stream.Client.Conn.SetReadDeadline(deadline)
	err2 := stream.Server.Conn.SetReadDeadline(deadline)

	return errors.Join(err1, err2)
}

func (stream *DuplexStream) Close() error {
	err1 := stream.Client.Conn.SetDeadline(time.Time{})
	err2 := stream.Server.Conn.SetDeadline(time.Time{})

	err3 := stream.Client.Conn.Close()
	err4 := stream.Server.Conn.Close()

	return errors.Join(err1, err2, err3, err4)
}

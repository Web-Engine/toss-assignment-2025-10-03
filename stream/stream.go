package stream

import (
	"bufio"
	"net"
)

type Stream struct {
	Conn *net.TCPConn

	Reader *bufio.Reader
	Writer *bufio.Writer
}

func NewStream(conn *net.TCPConn) *Stream {
	return &Stream{
		Conn:   conn,
		Reader: bufio.NewReader(conn),
		Writer: bufio.NewWriter(conn),
	}
}

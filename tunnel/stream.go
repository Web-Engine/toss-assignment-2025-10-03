package tunnel

import (
	"bufio"
	"net"
	"time"
)

type Stream struct {
	Conn net.Conn

	Reader *bufio.Reader
	Writer *bufio.Writer
}

func NewStream(conn net.Conn) *Stream {
	return &Stream{
		Conn:   conn,
		Reader: bufio.NewReader(conn),
		Writer: bufio.NewWriter(conn),
	}
}

// region net.Conn
func (s Stream) Read(b []byte) (n int, err error) {
	return s.Reader.Read(b)
}

func (s Stream) Write(b []byte) (n int, err error) {
	n, err1 := s.Writer.Write(b)
	if err1 != nil {
		return n, err1
	}

	err2 := s.Writer.Flush()
	return n, err2
}

func (s Stream) Close() error {
	return s.Conn.Close()
}

func (s Stream) LocalAddr() net.Addr {
	return s.Conn.LocalAddr()
}

func (s Stream) RemoteAddr() net.Addr {
	return s.Conn.RemoteAddr()
}

func (s Stream) SetDeadline(t time.Time) error {
	return s.Conn.SetDeadline(t)
}

func (s Stream) SetReadDeadline(t time.Time) error {
	return s.Conn.SetReadDeadline(t)
}

func (s Stream) SetWriteDeadline(t time.Time) error {
	return s.Conn.SetWriteDeadline(t)
}

// endregion

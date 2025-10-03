// main.go
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"syscall"
	"time"
)

const (
	listenAddr   = ":3129"          // TPROXY 대상으로 고정
	dialTimeout  = 10 * time.Second // 원래 목적지로 dialing timeout
	connDeadline = 5 * time.Minute  // 전체 connection deadline
)

func main() {
	listenConfig := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			err = c.Control(func(fd uintptr) {
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
			})

			return err
		},
	}

	listener, err := listenConfig.Listen(context.Background(), "tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", listenAddr, err)
	}
	defer listener.Close()

	log.Printf("tproxy-bypass (no-flags) listening on %s", listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}

type tcpConnectionIO struct {
	connection *net.TCPConn
	reader     *bufio.Reader
	writer     *bufio.Writer
}

func newTcpConnectionIO(conn *net.TCPConn) *tcpConnectionIO {
	return &tcpConnectionIO{
		connection: conn,
		reader:     bufio.NewReader(conn),
		writer:     bufio.NewWriter(conn),
	}
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()
	_ = clientConn.SetDeadline(time.Now().Add(connDeadline))

	localAddr := clientConn.LocalAddr()
	tcpLocal, ok := localAddr.(*net.TCPAddr)
	if !ok {
		log.Printf("unsupported local addr type: %T from %v", localAddr, clientConn.RemoteAddr())
		return
	}

	originalIP := tcpLocal.IP
	originalPort := tcpLocal.Port
	if originalIP == nil || originalPort == 0 {
		log.Printf("cannot determine original destination from LocalAddr=%v", localAddr)
		return
	}

	target := net.JoinHostPort(originalIP.String(), fmt.Sprintf("%d", originalPort))
	log.Printf("clientConn %s -> original %s", clientConn.RemoteAddr(), target)

	serverConn, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		log.Printf("dial original %s failed: %v", target, err)
		return
	}
	defer serverConn.Close()

	clientTcpConn, ok := clientConn.(*net.TCPConn)
	if !ok {
		log.Printf("TCP local connection expected: %T from %v", clientConn, clientConn.RemoteAddr())
		return
	}

	serverTcpConn, ok := serverConn.(*net.TCPConn)
	if !ok {
		log.Printf("TCP forward connection expected: %T from %v", serverConn, serverConn.RemoteAddr())
		return
	}

	_ = clientTcpConn.SetNoDelay(true)
	_ = serverTcpConn.SetNoDelay(true)

	clientIO := newTcpConnectionIO(clientTcpConn)
	serverIO := newTcpConnectionIO(serverTcpConn)
	_ = clientTcpConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_ = serverTcpConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))

	clientPeek, _ := clientIO.reader.Peek(1)
	serverPeek, _ := serverIO.reader.Peek(1)

	_ = clientTcpConn.SetReadDeadline(time.Time{})
	_ = serverTcpConn.SetReadDeadline(time.Time{})

	if len(clientPeek) > 0 {
		log.Printf("Client first protocol received")
		// Client-first protocol
		go pipeDuplex(clientIO, serverIO)
	} else if len(serverPeek) > 0 {
		// Server-first protocol
		log.Printf("Server first protocol received")
		go pipeDuplex(clientIO, serverIO)
	} else {
		// Loop again? or something
		// TODO
		return
	}

	// Pipe server to client
	chanErr := make(chan error, 2)
	go func() {
		_, err := io.Copy(serverConn, clientConn)
		if err == nil {
			_ = closeWrite(serverConn)
		}
		chanErr <- err
	}()

	// Pipe client to server
	go func() {
		_, err := io.Copy(clientConn, serverConn)
		if err == nil {
			_ = closeWrite(clientConn)
		}
		chanErr <- err
	}()

	if err := <-chanErr; err != nil && err != io.EOF {
		log.Printf("pipe error for %s <-> %s: %v", clientConn.RemoteAddr(), target, err)
	}
}

func pipeDuplex(clientIO, serverIO *tcpConnectionIO) {
	// TODO: error channel close
	go pipe(clientIO, serverIO)
	go pipe(serverIO, clientIO)
}

func pipe(from, to *tcpConnectionIO) {
	_, err := from.reader.WriteTo(to.writer)

	if err != nil {
		_ = closeWrite(from.connection)
	}
}

func closeWrite(c net.Conn) error {
	type cw interface{ CloseWrite() error }
	if x, ok := c.(cw); ok {
		return x.CloseWrite()
	}
	_ = c.SetDeadline(time.Now().Add(50 * time.Millisecond))
	return nil
}

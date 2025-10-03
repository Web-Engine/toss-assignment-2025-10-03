// main.go
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"syscall"
	"time"
	"toss/stream"
	"toss/stream/detector"
	"toss/stream/handler"
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

	duplexStream := stream.NewDuplexStreamFromConn(clientTcpConn, serverTcpConn)
	defer duplexStream.Close()

	_ = duplexStream.Client.Conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_ = duplexStream.Server.Conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))

	clientPeek, _ := duplexStream.Client.Reader.Peek(1)
	serverPeek, _ := duplexStream.Server.Reader.Peek(1)

	_ = duplexStream.Client.Conn.SetReadDeadline(time.Time{})
	_ = duplexStream.Server.Conn.SetReadDeadline(time.Time{})

	if len(clientPeek) > 0 {
		log.Printf("Client first protocol received")
		// Client-first protocol
		err = handleClientFirstProtocol(duplexStream)
	} else if len(serverPeek) > 0 {
		// Server-first protocol
		log.Printf("Server first protocol received")
		err = handleServerFirstProtocol(duplexStream)
	} else {
		// Loop again? or something
		// TODO
	}

	if err != nil {
		log.Printf("Error processing stream: %v", err)
	}
}

func handleClientFirstProtocol(duplex *stream.DuplexStream) error {
	protocols := []struct {
		detector stream.Detector
		handler  stream.Handler
	}{
		{detector: detector.NewHttp11Detector(), handler: handler.NewHttp11Handler()},
		{detector: detector.NewHttp2Detector(), handler: handler.NewHttp2Handler()},
		{detector: detector.NewTlsDetector(), handler: handler.NewTlsHandler()},
	}

	var streamHandler stream.Handler

	if err := duplex.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		return err
	}

	for _, protocol := range protocols {
		if protocol.detector.Detect(duplex, context.Background()) {
			streamHandler = protocol.handler
		}
	}

	if err := duplex.SetReadDeadline(time.Time{}); err != nil {
		return err
	}

	if streamHandler == nil {
		streamHandler = handler.NewPipeHandler()
	}

	return streamHandler.Handle(duplex)
}

func handleServerFirstProtocol(duplex *stream.DuplexStream) error {
	pipe := handler.NewPipeHandler()

	return pipe.Handle(duplex)
}

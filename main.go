// main.go
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"syscall"
	"time"
	"toss/cert"
	"toss/tunnel"
	"toss/tunnel/detector"
	"toss/tunnel/handler"
)

const (
	listenAddr   = ":3129"          // TPROXY 대상으로 고정
	dialTimeout  = 10 * time.Second // 원래 목적지로 dialing timeout
	connDeadline = 5 * time.Minute  // 전체 connection deadline
)

var certManager *cert.Manager

func main() {
	cm, err := cert.NewCertManager("./tls/rootCA.pem", "./tls/rootCA.key")
	if err != nil {
		log.Fatalf("create cert manager: %v", err)
	}
	certManager = cm

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

	tun := tunnel.NewTunnelFromConn(clientTcpConn, serverTcpConn)
	defer tun.Close()

	_ = tun.Downstream.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_ = tun.Upstream.SetReadDeadline(time.Now().Add(200 * time.Millisecond))

	clientPeek, _ := tun.Downstream.Reader.Peek(1)
	serverPeek, _ := tun.Upstream.Reader.Peek(1)

	_ = tun.Downstream.SetReadDeadline(time.Time{})
	_ = tun.Upstream.SetReadDeadline(time.Time{})

	if len(clientPeek) > 0 {
		log.Printf("Downstream first protocol received")
		// Downstream-first protocol
		err = handleClientFirstProtocol(tun)
	} else if len(serverPeek) > 0 {
		// Upstream-first protocol
		log.Printf("Upstream first protocol received")
		err = handleServerFirstProtocol(tun)
	} else {
		// Loop again? or something
		// TODO
	}

	if err != nil {
		log.Printf("Error processing tunnel: %v", err)
	}
}

func handleClientFirstProtocol(tun *tunnel.Tunnel) error {
	protocols := []handler.ProtocolHandler{
		{Detector: detector.NewHttp11Detector(), Handler: handler.NewHttp11Handler()},
		{Detector: detector.NewHttp2Detector(), Handler: handler.NewHttp2Handler()},
		{Detector: detector.NewTlsDetector(), Handler: handler.NewTlsHandler(certManager.GetCertificate)},
	}

	tunHandler := handler.NewClientFirstHandler(protocols)

	return tunHandler.Handle(tun)
}

func handleServerFirstProtocol(tun *tunnel.Tunnel) error {
	pipe := handler.NewPipeHandler()

	return pipe.Handle(tun)
}

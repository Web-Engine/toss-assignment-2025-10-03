// main.go
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"syscall"
	"time"
	"toss/cert"
	"toss/tunnel"
	"toss/tunnel/detector"
	"toss/tunnel/handler"
)

const (
	listenAddr  = ":3129"
	dialTimeout = 10 * time.Second
)

var certManager *cert.Manager

func main() {
	var err error
	initLogger()

	certManager, err = cert.NewCertManager("./tls/rootCA.pem", "./tls/rootCA.key")
	if err != nil {
		slog.Error("init cert manager", slog.Any("error", err))
		return
	}

	listener, err := initListener()
	if err != nil {
		slog.Error("init listener", slog.Any("error", err))
		return
	}

	defer listener.Close()

	slog.Info(fmt.Sprintf("listening on %s", listener.Addr()))

	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Error("accept", slog.Any("error", err))
			continue
		}

		go handleConnection(conn)
	}
}

func initLogger() {
	slogJsonHandler := slog.NewJSONHandler(os.Stdout, nil)
	logger := slog.New(slogJsonHandler)

	slog.SetDefault(logger)
	slog.SetLogLoggerLevel(slog.LevelDebug)
}

func initListener() (net.Listener, error) {
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

	return listener, err
}

func handleConnection(downstreamConn net.Conn) {
	defer downstreamConn.Close()

	srcAddr := downstreamConn.RemoteAddr()
	dstAddr := downstreamConn.LocalAddr()

	logger := slog.Default().With(
		slog.Any("src", srcAddr),
		slog.Any("dst", dstAddr),
	)

	logger.Debug(fmt.Sprintf("connection request: %v -> %v", srcAddr, dstAddr))

	upstreamConn, err := net.DialTimeout("tcp", dstAddr.String(), dialTimeout)
	if err != nil {
		logger.Error("failed to dial to dst", slog.Any("error", err))
		return
	}
	defer upstreamConn.Close()

	downstreamTCPConn, ok := downstreamConn.(*net.TCPConn)
	if !ok {
		logger.Error("downstream connection is not tcp")
		return
	}

	upstreamTCPConn, ok := upstreamConn.(*net.TCPConn)
	if !ok {
		logger.Error("upstream connection is not tcp")
		return
	}

	_ = downstreamTCPConn.SetNoDelay(true)
	_ = upstreamTCPConn.SetNoDelay(true)

	tun := tunnel.NewTunnelFromConn(downstreamTCPConn, upstreamTCPConn)
	defer tun.Close()

	handleTunnel(tun)
}

func handleTunnel(tun *tunnel.Tunnel) {
	for i := 0; i < 5; i++ {
		_ = tun.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = tun.Downstream.Reader.Peek(1)
		_, _ = tun.Upstream.Reader.Peek(1)
		_ = tun.SetReadDeadline(time.Time{})

		if tun.Downstream.Reader.Buffered() > 0 {
			handleClientFirstProtocol(tun)
			return
		}

		if tun.Upstream.Reader.Buffered() > 0 {
			handleServerFirstProtocol(tun)
			return
		}
	}

	slog.Error("failed to read packet")
}

func handleClientFirstProtocol(tun *tunnel.Tunnel) {
	protocols := []handler.ProtocolHandler{
		{Detector: detector.NewHttp11Detector(), Handler: handler.NewHttp11Handler()},
		{Detector: detector.NewHttp2Detector(), Handler: handler.NewHttp2Handler()},
		{Detector: detector.NewTlsDetector(), Handler: handler.NewTlsHandler(certManager.GetCertificate)},
	}

	tunHandler := handler.NewClientFirstHandler(protocols)

	if err := tunHandler.Handle(tun); err != nil && err != io.EOF {
		slog.Error("error occurred", slog.Any("error", err))
	}
}

func handleServerFirstProtocol(tun *tunnel.Tunnel) {
	byPassHandler := handler.NewByPassHandler()

	if err := byPassHandler.Handle(tun); err != nil && err != io.EOF {
		slog.Error("error occurred", slog.Any("error", err))
	}
}

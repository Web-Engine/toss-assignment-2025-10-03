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
	slogJsonHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := slog.New(slogJsonHandler)

	slog.SetDefault(logger)
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
		"src", srcAddr.String(),
		"dst", dstAddr.String(),
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

	tun := tunnel.NewTunnelFromConn(srcAddr, dstAddr, downstreamTCPConn, upstreamTCPConn)
	defer tun.Close()

	logger = slog.Default().With(
		slog.Group("tunnel",
			"id", tun.ID(),
			"src", srcAddr.String(),
			"dst", dstAddr.String(),
		),
	)
	logger.Debug("tunnel created")

	handleTunnel(tun, logger)
}

func handleTunnel(tun *tunnel.Tunnel, logger *slog.Logger) {
	logger.Debug("tunnel handling start")

	deadline := time.Now().Add(5 * time.Second)

	// TODO: spin lock하지말고 goroutine으로 먼저 온쪽을 처리하도록 개선 필요
	for deadline.After(time.Now()) {
		logger.Debug("Try to detect client-side or server-side first protocol")

		_ = tun.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		_, _ = tun.Downstream.Reader.Peek(1)
		_, _ = tun.Upstream.Reader.Peek(1)
		_ = tun.SetReadDeadline(time.Time{})

		if tun.Downstream.Reader.Buffered() > 0 {
			logger.Debug("client-side first protocol detected")
			handleClientFirstProtocol(tun, logger)
			return
		}

		if tun.Upstream.Reader.Buffered() > 0 {
			logger.Debug("server-side first protocol detected")
			handleServerFirstProtocol(tun, logger)
			return
		}
	}

	logger.Error("failed to read packet")
}

func handleClientFirstProtocol(tun *tunnel.Tunnel, logger *slog.Logger) {
	detectors := []tunnel.Detector{
		detector.NewHttp11Detector(logger),
		detector.NewHttp2Detector(logger),
		detector.NewTlsDetector(logger, certManager),
	}

	detectHandler := handler.NewDetectHandler(logger, detectors)

	if err := detectHandler.Handle(tun); err != nil && err != io.EOF {
		logger.Error("error occurred", "error", err, "stack", err.Error())
	}
}

func handleServerFirstProtocol(tun *tunnel.Tunnel, logger *slog.Logger) {
	byPassHandler := handler.NewByPassHandler(logger)

	if err := byPassHandler.Handle(tun); err != nil && err != io.EOF {
		logger.Error("error occurred", slog.Any("error", err))
	}
}

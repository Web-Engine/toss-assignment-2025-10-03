package handler

import (
	"context"
	"io"
	"log/slog"
	"toss/tunnel"

	"golang.org/x/sync/errgroup"
)

type ByPassHandler struct {
	logger *slog.Logger
}

func NewByPassHandler(logger *slog.Logger) *ByPassHandler {
	return &ByPassHandler{
		logger: logger,
	}
}

func (h *ByPassHandler) Handle(tun *tunnel.Tunnel) error {
	logger := h.logger.With("context", "ByPassHandler")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)

	logger.Debug("bypass start")
	g.Go(func() error { return pipe(tun.Downstream, tun.Upstream) })
	g.Go(func() error { return pipe(tun.Upstream, tun.Downstream) })

	err := g.Wait()
	logger.Debug("bypass end")

	return err
}

func pipe(from, to *tunnel.Stream) error {
	if n := from.Reader.Buffered(); n > 0 {
		peeked, err := from.Reader.Peek(n)
		if err != nil {
			return err
		}

		for written := 0; written < n; {
			w, err := to.Conn.Write(peeked[written:])

			if err != nil {
				return err
			}

			written += w
		}

		if _, err := from.Reader.Discard(n); err != nil {
			return err
		}

	}

	_, err := io.Copy(to.Conn, from.Conn)
	return err
}

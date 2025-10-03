package handler

import (
	"context"
	"io"
	"toss/tunnel"

	"golang.org/x/sync/errgroup"
)

type PipeHandler struct{}

func NewPipeHandler() *PipeHandler {
	return &PipeHandler{}
}

func (handler *PipeHandler) Handle(tun *tunnel.Tunnel) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return pipe(tun.Downstream, tun.Upstream) })
	g.Go(func() error { return pipe(tun.Upstream, tun.Downstream) })

	return g.Wait()
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

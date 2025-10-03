package handler

import (
	"errors"
	"toss/tunnel"
)

type Http2Handler struct {
}

func NewHttp2Handler() *Http2Handler {
	return &Http2Handler{}
}

func (h *Http2Handler) Handle(tun *tunnel.Tunnel) error {
	return errors.New("Not Implemented")
}

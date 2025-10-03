package handler

import (
	"errors"
	"toss/stream"
)

type Http2Handler struct {
}

func NewHttp2Handler() *Http2Handler {
	return &Http2Handler{}
}

func (h *Http2Handler) Handle(stream *stream.DuplexStream) error {
	return errors.New("Not Implemented")
}

package stream

type Handler interface {
	Handle(stream *DuplexStream) error
}

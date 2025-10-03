package protocol

const (
	ProtocolUnknown = 0
	ProtocolTls     = 1 << 1

	ProtocolHttp11 = 1 << 2
	ProtocolHttp2  = 1 << 3
	ProtocolHttp3  = 1 << 4

	ProtocolByPass = 1 << 5
)

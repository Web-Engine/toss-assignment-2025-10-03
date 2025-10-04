package detector

import (
	"fmt"
	"log/slog"
	"net"
	"toss/cert"
	"toss/tunnel"
	"toss/tunnel/handler"
)

type TlsDetector struct {
	logger      *slog.Logger
	certManager *cert.Manager
}

func NewTlsDetector(logger *slog.Logger, certManager *cert.Manager) *TlsDetector {
	return &TlsDetector{
		logger:      logger,
		certManager: certManager,
	}
}

var (
	allowIpList = []net.IP{
		net.IPv4(1, 1, 1, 1),
	}
	allowDomainList = []string{
		"www.example.com",
		"toss.im",
	}
)

const (
	tlsRecordHeaderLen = 5
	maxTlsRecordSize   = 1 << 16

	tlsContentTypeHandshake = 0x16

	tlsHandshakeMessageTypeClientHello         = 1
	tlsHandshakeClientHelloExtensionServerName = 0

	tlsNameTypeHostName = 0
)

func (d *TlsDetector) Detect(tun *tunnel.Tunnel) (tunnel.DetectResult, tunnel.Handler) {
	logger := d.logger.With("context", "TlsDetector")

	// TLS Record structure
	// <5 byte> TLS Record Header
	// <n byte> TLS Record Payload

	// TLS Record Header
	// <1 byte> ContentType
	//  - 0x14: ChangeCipherSpec,
	//  - 0x15: Alert
	//  - 0x16: Handshake
	//  - 0x17: Application
	//  - 0x18: Heartbeat
	// <2 byte> ProtocolVersion (major 1byte, minor 1byte)
	//  - 3.0: SSL 3.0
	//  - 3.1: TLS 1.0
	//  - 3.2: TLS 1.1
	//  - 3.3: TLS 1.2
	//  - 3.4: TLS 1.3
	// <2 byte> Record Payload Length
	header, err := tun.Downstream.Reader.Peek(tlsRecordHeaderLen)
	if err != nil {
		logger.Debug("tls protocol: possible: failed to peek tls record header (buffer maybe not ready)")
		return tunnel.DetectResultPossible, nil
	}

	tlsContentType := header[0]
	versionMajor := header[1]
	versionMinor := header[2]
	payloadLen := int(header[3])<<8 | int(header[4])

	if tlsContentType != tlsContentTypeHandshake {
		logger.Debug("tls protocol: never: tls content type mismatch", "tlsContentType", tlsContentType)
		return tunnel.DetectResultNever, nil
	}

	// 3.0 ~ 3.4
	if versionMajor != 3 || versionMinor > 4 {
		logger.Debug("tls protocol: never: tls version mismatch", "tlsVersionMajor", versionMajor, "tlsVersionMinor", versionMinor)
		return tunnel.DetectResultNever, nil
	}

	if payloadLen <= 0 || payloadLen > maxTlsRecordSize {
		logger.Debug("tls protocol: never: wrong payload length", "payloadLength", payloadLen)
		return tunnel.DetectResultNever, nil
	}

	recordLen := tlsRecordHeaderLen + payloadLen
	record, err := tun.Downstream.Reader.Peek(recordLen)
	if err != nil {
		logger.Debug("tls protocol: possible: failed to peek record (buffer maybe not ready)")
		return tunnel.DetectResultPossible, nil
	}

	// Handshake Payload Structure
	// <1 byte> Message Type
	//  - 0:  HelloRequest
	//  - 1:  ClientHello
	//  - 2:  ServerHello
	//  - 4:  NewSessionTicket
	//  - 8:  EncryptedExtensions (TLS 1.3 only)
	//  - 11: Certificate
	//  - 12: ServerKeyExchange
	//  - 13: CertificateRequest
	//  - 14: ServerHelloDone
	//  - 15: CertificateVerify
	//  - 16: ClientKeyExchange
	//  - 20: Finished
	// <repeat>
	//   <3 byte> Handshake Length
	//   <n byte> Handshake Message
	payload := record[tlsRecordHeaderLen:]
	if len(payload) < 4 {
		logger.Debug("tls protocol: never: wrong payload slice length")
		return tunnel.DetectResultNever, nil
	}

	handshakeType := payload[0]
	if handshakeType != tlsHandshakeMessageTypeClientHello {
		logger.Debug("tls protocol: never: handshake type mismatch", "handshakeType", handshakeType)
		return tunnel.DetectResultNever, nil
	}

	handshakeLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if handshakeLen < 0 {
		logger.Debug("tls protocol: never: wrong handshake length", "handshakeLength", handshakeLen)
		return tunnel.DetectResultNever, nil
	}

	// ClientHello structure
	// < 2 byte> Message Version
	// <32 byte> Random
	// < 1 byte> Session ID Length
	// < n byte> Session ID
	// < 2 byte> Cipher Suites Len
	// < n byte> Cipher Suites
	// < 1 byte> Compression Methods Len
	// < n byte> Compression Methods
	// < 2 byte> Extensions Len
	// <repeat> Extension
	//   <2 byte> Ext Type
	//    - 0: server_name
	//    - 1: max_fragment_length
	//    - 2: client_certificate_url
	//    - 3: trusted_ca_keys
	//    - 4: truncated_hmac
	//    - 5: status_request
	//   <2 byte> Ext Length
	//   <n byte> Ext Data
	if len(payload) < 4+handshakeLen {
		logger.Debug("tls protocol: never: payload slice less than handshake length", "handshakeLength", handshakeLen)
		return tunnel.DetectResultNever, nil
	}

	clientHello := payload[4 : 4+handshakeLen]

	// Message Version
	clientHello = clientHello[2:]

	// Random
	clientHello = clientHello[32:]

	// Session ID Length
	if len(clientHello) < 1 {
		logger.Debug("tls protocol: never: wrong clientHello slice length")
		return tunnel.DetectResultNever, nil
	}
	sessionIdLen := int(clientHello[0])
	clientHello = clientHello[1:]
	if sessionIdLen <= 0 {
		logger.Debug("tls protocol: never: wrong sessionId length", "sessionIdLength", sessionIdLen)
		return tunnel.DetectResultNever, nil
	}

	// Session ID
	clientHello = clientHello[sessionIdLen:]

	// Cipher Suites Len
	if len(clientHello) < 2 {
		logger.Debug("tls protocol: never: wrong clientHello slice length")
		return tunnel.DetectResultNever, nil
	}
	cipherSuitesLen := int(clientHello[0])<<8 | int(clientHello[1])
	clientHello = clientHello[2:]
	if cipherSuitesLen <= 0 {
		logger.Debug("tls protocol: never: wrong cipherSuitesLen", "cipherSuitesLen", cipherSuitesLen)
		return tunnel.DetectResultNever, nil
	}

	// Cipher Suites
	clientHello = clientHello[cipherSuitesLen:]

	// Compression Methods Len
	if len(clientHello) < 1 {
		logger.Debug("tls protocol: never: wrong clientHello slice length")
		return tunnel.DetectResultNever, nil
	}
	compressionMethodsLen := int(clientHello[0])
	clientHello = clientHello[1:]
	if compressionMethodsLen <= 0 {
		logger.Debug("tls protocol: never: wrong compressionMethodsLen", "compressionMethodsLen", compressionMethodsLen)
		return tunnel.DetectResultNever, nil
	}

	// Compression Methods
	clientHello = clientHello[compressionMethodsLen:]

	// Extensions Len
	if len(clientHello) < 2 {
		logger.Debug("tls protocol: never: wrong clientHello slice length")
		return tunnel.DetectResultNever, nil
	}

	extensionsLen := int(clientHello[0])<<8 | int(clientHello[1])
	clientHello = clientHello[2:]
	if extensionsLen <= 0 {
		logger.Debug("tls protocol: matched")
		return tunnel.DetectResultMatched, handler.NewTlsHandler(d.logger, d.certManager)
	}

	// Extensions
	if len(clientHello) < extensionsLen {
		logger.Debug("tls protocol: never: wrong clientHello slice length")
		return tunnel.DetectResultNever, nil
	}

	extensions := clientHello
	var serverNameList []string

	for len(extensions) != 0 {
		if len(extensions) < 4 {
			break
		}

		extType := int(extensions[0])<<8 | int(extensions[1])
		extLen := int(extensions[2])<<8 | int(extensions[3])
		extensions = extensions[4:]

		if extLen <= 0 {
			continue
		}

		if len(extensions) < extLen {
			break
		}

		ext := extensions[:extLen]

		if extType != tlsHandshakeClientHelloExtensionServerName {
			extensions = extensions[extLen:]
			continue
		}

		// ServerNameList structure
		// <2 byte> ServerNameList Len
		// <repeat> ServerName
		//   <1 byte> NameType
		//    - 0: HostName
		//   <when NameType is HostName>
		//     <2 byte> HostName Len
		//     <n byte> HostName
		if len(ext) < 2 {
			break
		}

		serverNameListLen := int(ext[0])<<8 | int(ext[1])
		ext = ext[2:]

		for i := 0; i < serverNameListLen; i++ {
			// NameType
			if len(ext) < 1 {
				break
			}

			nameType := int(ext[0])
			ext = ext[1:]
			if nameType != tlsNameTypeHostName {
				break
			}

			// HostName Len
			if len(ext) < 2 {
				break
			}
			hostNameLen := int(ext[0])<<8 | int(ext[1])
			ext = ext[2:]

			if len(ext) < hostNameLen {
				break
			}

			serverName := string(ext[:hostNameLen])
			serverNameList = append(serverNameList, serverName)
		}
		break
	}

	logger.Debug("tls protocol: matched")

	dstTcpAddr, ok := tun.Dst.(*net.TCPAddr)
	if ok {
		for _, allowIp := range allowIpList {
			if dstTcpAddr.IP.Equal(allowIp) {
				logger.Info(fmt.Sprintf("%v in allowed ip list: bypass", dstTcpAddr))
				byPassLogger := d.logger.With(
					"bypass-by", "TlsDetector",
					"allowed-ip", dstTcpAddr.String(),
				)

				return tunnel.DetectResultMatched, handler.NewByPassHandler(byPassLogger)
			}
		}
	}

	for _, allowServerName := range allowDomainList {
		for _, serverName := range serverNameList {
			if serverName == allowServerName {
				logger.Info(fmt.Sprintf("%v in allowed domain list: bypass", serverName))
				byPassLogger := d.logger.With(
					"bypass-by", "TlsDetector",
					"tlsServerNameList", serverNameList,
					"matchedServerName", serverName,
				)
				return tunnel.DetectResultMatched, handler.NewByPassHandler(byPassLogger)
			}
		}
	}

	nextLogger := d.logger.With("tlsServerNameList", serverNameList)
	return tunnel.DetectResultMatched, handler.NewTlsHandler(nextLogger, d.certManager)
}

package detector

import (
	"context"
	"log"
	"toss/tunnel"
)

type TlsDetector struct {
}

func NewTlsDetector() *TlsDetector {
	return &TlsDetector{}
}

var (
	allowList = []string{
		"www.example.com",
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

func (detector *TlsDetector) Detect(tun *tunnel.Tunnel, ctx context.Context) bool {
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
	// <2 byte> Length
	header, err := tun.Downstream.Reader.Peek(tlsRecordHeaderLen)
	if err != nil {
		return false
	}

	if header[0] != tlsContentTypeHandshake {
		return false
	}

	versionMajor := header[1]
	versionMinor := header[2]

	// 3.0 ~ 3.4
	if versionMajor != 3 || versionMinor > 4 {
		return false
	}

	payloadLen := int(header[3])<<8 | int(header[4])
	if payloadLen <= 0 || payloadLen > maxTlsRecordSize {
		return false
	}

	recordLen := tlsRecordHeaderLen + payloadLen
	record, err := tun.Downstream.Reader.Peek(recordLen)
	if err != nil {
		return false
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
		return false
	}

	handshakeType := payload[0]
	if handshakeType != tlsHandshakeMessageTypeClientHello {
		return false
	}

	handshakeLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if handshakeLen < 0 {
		return false
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
		return false
	}

	clientHello := payload[4 : 4+handshakeLen]

	// Message Version
	clientHello = clientHello[2:]

	// Random
	clientHello = clientHello[32:]

	// Session ID Length
	if len(clientHello) < 1 {
		return false
	}
	sessionIdLen := int(clientHello[0])
	clientHello = clientHello[1:]
	if sessionIdLen <= 0 {
		return false
	}

	// Session ID
	clientHello = clientHello[sessionIdLen:]

	// Cipher Suites Len
	if len(clientHello) < 2 {
		return false
	}
	cipherSuitesLen := int(clientHello[0])<<8 | int(clientHello[1])
	clientHello = clientHello[2:]
	if cipherSuitesLen <= 0 {
		return false
	}

	// Cipher Suites
	clientHello = clientHello[cipherSuitesLen:]

	// Compression Methods Len
	if len(clientHello) < 1 {
		return false
	}
	compressionMethodsLen := int(clientHello[0])
	clientHello = clientHello[1:]
	if compressionMethodsLen <= 0 {
		return false
	}

	// Compression Methods
	clientHello = clientHello[compressionMethodsLen:]

	// Extensions Len
	if len(clientHello) < 2 {
		return false
	}

	extensionsLen := int(clientHello[0])<<8 | int(clientHello[1])
	clientHello = clientHello[2:]
	if extensionsLen <= 0 {
		return false
	}

	// Extensions
	if len(clientHello) < extensionsLen {
		return false
	}

	if extensionsLen != len(clientHello) {
		return false
	}

	extensions := clientHello
	var serverNameList []string

	for {
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
			continue
		}

		serverNameListLen := int(ext[0])<<8 | int(ext[1])
		ext = ext[2:]

		for i := 0; i < serverNameListLen; i++ {
			// NameType
			if len(ext) < 1 {
				continue
			}

			nameType := int(ext[0])
			if nameType != tlsNameTypeHostName {
				continue
			}
			ext = ext[1:]

			// HostName Len
			if len(ext) < 2 {
				continue
			}
			hostNameLen := int(ext[0])<<8 | int(ext[1])
			ext = ext[2:]

			if len(ext) < hostNameLen {
				continue
			}

			serverName := string(ext[:hostNameLen])
			serverNameList = append(serverNameList, serverName)
		}
	}

	log.Printf("server name: %v", serverNameList)

	return true
}

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	nfq "github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket/layers"
)

func main() {
	queue, err := nfq.NewNFQueue(0, 100, nfq.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		log.Fatalf("failed to create nfqueue: %v", err)
	}
	defer queue.Close()

	log.Printf("nfqueue started")

	go processQueue(queue)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}

func processQueue(queue *nfq.NFQueue) {
	packetChan := queue.GetPackets()
	log.Printf("Starting processing queue")

	for packet := range packetChan {
		log.Printf("received packet")
		go processPacket(packet)
	}
}

func processPacket(packet nfq.NFPacket) {
	layerIPv4 := packet.Packet.Layer(layers.LayerTypeIPv4)
	if layerIPv4 == nil {
		return
	}

	layerTCP := packet.Packet.Layer(layers.LayerTypeTCP)
	if layerTCP == nil {
		return
	}

	payload := layerTCP.LayerPayload()
	log.Printf("payload length: %v", len(payload))
}

// // helpers

// func min(a, b int) int {
// 	if a < b {
// 		return a
// 	}
// 	return b
// }

// func isIPv4(pkt []byte) bool {
// 	if len(pkt) < 1 {
// 		return false
// 	}
// 	return (pkt[0] >> 4) == 4
// }

// func ipProto(pkt []byte) byte {
// 	if len(pkt) < 10 {
// 		return 0
// 	}
// 	return pkt[9]
// }

// func isHTTP(payload []byte) bool {
// 	if len(payload) < 3 {
// 		return false
// 	}
// 	// 간단 체크: 메서드로 시작하는지
// 	methods := [][]byte{
// 		[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "),
// 		[]byte("DELETE "), []byte("OPTIONS "), []byte("CONNECT "), []byte("PATCH "),
// 	}
// 	for _, m := range methods {
// 		if len(payload) >= len(m) && string(payload[:len(m)]) == string(m) {
// 			return true
// 		}
// 	}
// 	return false
// }

// func isTLSClientHello(payload []byte) bool {
// 	// TLS record header: 0: type(0x16=handshake), 1-2 version, 3-4 length
// 	// Handshake header begins at payload[5], handshake type 0x01 = ClientHello
// 	if len(payload) < 6 {
// 		return false
// 	}
// 	if payload[0] != 0x16 {
// 		return false
// 	}
// 	// payload[5] should be 0x01
// 	return payload[5] == 0x01
// }

// func ipToStr(b []byte) string {
// 	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
// }

// func addIptableMark(src, dst string, sport, dport uint16) {
// 	// 먼저 존재하는지 검사 (iptables -t mangle -C PREROUTING ...)
// 	checkArgs := []string{"-t", "mangle", "-C", "PREROUTING",
// 		"-s", src, "-d", dst, "-p", "tcp",
// 		"--sport", fmt.Sprint(sport), "--dport", fmt.Sprint(dport),
// 		"-j", "MARK", "--set-mark", "1",
// 	}
// 	if runCmdSilent("iptables", checkArgs...) == nil {
// 		// 이미 존재
// 		return
// 	}
// 	// 존재하지 않으면 삽입
// 	insertArgs := []string{"-t", "mangle", "-I", "PREROUTING",
// 		"-s", src, "-d", dst, "-p", "tcp",
// 		"--sport", fmt.Sprint(sport), "--dport", fmt.Sprint(dport),
// 		"-j", "MARK", "--set-mark", "1",
// 	}
// 	if err := runCmdSilent("iptables", insertArgs...); err != nil {
// 		log.Printf("failed to add iptables mark rule: %v\n", err)
// 	} else {
// 		log.Printf("added iptables mark rule: %s:%d -> %s:%d\n", src, sport, dst, dport)
// 	}
// }

// func runCmdSilent(name string, args ...string) error {
// 	cmd := exec.Command(name, args...)
// 	// discard output normally
// 	cmd.Stdout = nil
// 	cmd.Stderr = nil
// 	return cmd.Run()
// }

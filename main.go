package main

import (
	"context"
	"log"
	"os/signal"
	"sync"
	"syscall"

	nfq "github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket/layers"
)

const numWorkers = 4

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	queue, err := nfq.NewNFQueue(1, 100, nfq.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		log.Fatalf("failed to create nfqueue: %v", err)
	}
	defer queue.Close()

	log.Printf("nfqueue started")
	var wg sync.WaitGroup

	packetChan := queue.GetPackets()

	for i := 1; i <= numWorkers; i++ {
		wg.Add(1)
		go worker(packetChan, ctx, &wg)
	}

	// Wait exit signal
	<-ctx.Done()

	// Wait workgroup end
	wg.Wait()
}

func worker(packetChan <-chan nfq.NFPacket, ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	log.Printf("worker started")

	for {
		select {
		case <-ctx.Done():
			return

		case packet, ok := <-packetChan:
			log.Printf("received packet %v", packet)
			if !ok {
				return
			}

			process(packet)
		}
	}
}

func process(packet nfq.NFPacket) {
	transportLayer := packet.Packet.TransportLayer()

	if transportLayer != nil {
		packet.SetVerdict(nfq.NF_ACCEPT)
		log.Printf("There are no transport layer")
		return
	}

	if transportLayer.LayerType() != layers.LayerTypeTCP {
		log.Printf("Packet is not a TCP layer: %v", transportLayer.LayerType())
		return
	}

	payload := transportLayer.LayerPayload()
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

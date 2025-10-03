package main

import (
	"context"
	"log"
	"os/signal"
	"sync"
	"syscall"
	"toss/pfqueue_detector"
	"toss/pfqueue_stream"

	nfq "github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

const numQueueWorkers = 4

type assembleInput struct {
	flow gopacket.Flow
	tcp  *layers.TCP
}

type workerContext struct {
	ctx          context.Context
	wg           *sync.WaitGroup
	queue        *nfq.NFQueue
	id           int
	table        *pfqueue_stream.Table
	assemblyChan chan *assembleInput
}

func pfqueue_main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("nfqueue creating")

	queues := make([]*nfq.NFQueue, numQueueWorkers)
	for i := 0; i < numQueueWorkers; i++ {
		queue, err := nfq.NewNFQueue(uint16(i), 100, nfq.NF_DEFAULT_PACKET_SIZE)
		if err != nil {
			log.Panicf("Failed to create queue(%v): %v", i, err)
		}

		defer queue.Close()
		queues[i] = queue
	}

	log.Printf("nfqueue ready")

	dtr := &pfqueue_detector.Detector{}
	table := pfqueue_stream.NewTable(dtr)
	pool := tcpassembly.NewStreamPool(table)
	assembler := tcpassembly.NewAssembler(pool)

	assemblerChan := make(chan *assembleInput)

	go assemblerWorker(assemblerChan, assembler)

	var wg sync.WaitGroup

	for i := 0; i < numQueueWorkers; i++ {
		workerCtx := &workerContext{
			id:           i,
			table:        table,
			queue:        queues[i],
			ctx:          ctx,
			wg:           &wg,
			assemblyChan: assemblerChan,
		}
		wg.Add(1)
		go queueWorker(workerCtx)
	}

	// Wait exit signal
	<-ctx.Done()

	// Wait workgroup end
	wg.Wait()
}

func queueWorker(ctx *workerContext) {
	defer ctx.wg.Done()
	log.Printf("Worker#%v: started", ctx.id)
	defer log.Printf("Worker#%v: exited", ctx.id)

	packetChan := ctx.queue.GetPackets()

	for {
		select {
		case <-ctx.ctx.Done():
			return

		case packet, ok := <-packetChan:
			log.Printf("Worker#%v: received packet", ctx.id)
			if !ok {
				return
			}

			processPacket(&packet, ctx)
		}
	}
}

func processPacket(packet *nfq.NFPacket, ctx *workerContext) {
	ipv4Layer := packet.Packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcpLayer := packet.Packet.Layer(layers.LayerTypeTCP).(*layers.TCP)

	if ipv4Layer == nil {
		packet.SetVerdict(nfq.NF_ACCEPT)
		log.Printf("We supports only IPv4")
		return
	}

	if tcpLayer == nil {
		packet.SetVerdict(nfq.NF_ACCEPT)
		log.Printf("Packet is not a TCP layer: %v", tcpLayer.LayerType())
		return
	}

	ipv4Flow := ipv4Layer.NetworkFlow()
	tcpFlow := tcpLayer.TransportFlow()

	key := ipv4Flow.String() + "|" + tcpFlow.String()

	flow := ctx.table.GetOrCreate(key)

	flow.Lock()
	defer flow.Unlock()

	if flow.IsDecided() {
		packet.SetVerdictMark(nfq.NF_ACCEPT, flow.Mark())
		return
	}

	if tcpLayer.SYN {
		packet.SetVerdict(nfq.NF_ACCEPT)
		return
	}

	flow.AddPacket(packet)

	ctx.assemblyChan <- &assembleInput{flow: ipv4Flow, tcp: tcpLayer}

	payload := tcpLayer.LayerPayload()
	log.Printf("payload length: %v", len(payload))
	log.Printf("syn: %v, ack: %v", tcpLayer.SYN, tcpLayer.ACK)

	//packet.SetVerdict(nfq.NF_DROP)
}

func assemblerWorker(assemblyChan chan *assembleInput, assembler *tcpassembly.Assembler) {
	for input := range assemblyChan {
		assembler.Assemble(input.flow, input.tcp)
		assembler.FlushAll()
	}
}

package stream

import (
	"log"
	"time"

	nfq "github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket/tcpassembly"
)

func (flow *Flow) Reassembled(reassemblies []tcpassembly.Reassembly) {
	log.Printf("Reassembling %d packets", len(reassemblies))
	flow.Lock()
	defer flow.Unlock()

	for _, reassemble := range reassemblies {
		if len(reassemble.Bytes) == 0 {
			continue
		}

		flow.buf.Write(reassemble.Bytes)
		flow.last = time.Now()

		if flow.IsDecided() {
			break
		}

		mark := flow.table.detector.Analyze(flow.buf)
		flow.mark = mark

		if flow.IsDecided() {
			flow.SetVerdictMark(nfq.NF_ACCEPT, mark)
		}
	}
}

func (flow *Flow) ReassemblyComplete() {
	//TODO implement me
	log.Printf("Reassembling complete")
}

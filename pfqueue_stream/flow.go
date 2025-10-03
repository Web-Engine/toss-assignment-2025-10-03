package pfqueue_stream

import (
	"bytes"
	"sync"
	"time"

	nfq "github.com/AkihiroSuda/go-netfilter-queue"
)

type Flow struct {
	key   string
	table *Table

	mutex   sync.Mutex
	buf     bytes.Buffer
	packets []*nfq.NFPacket
	mark    uint32
	last    time.Time
}

func NewFlow(key string, table *Table) *Flow {
	return &Flow{
		key:   key,
		table: table,

		mutex:   sync.Mutex{},
		buf:     bytes.Buffer{},
		packets: []*nfq.NFPacket{},
		mark:    0,
		last:    time.Now(),
	}
}

func (flow *Flow) Lock() {
	flow.mutex.Lock()
}

func (flow *Flow) Unlock() {
	flow.mutex.Unlock()
}

func (flow *Flow) AddPacket(packet *nfq.NFPacket) {
	flow.packets = append(flow.packets, packet)
}

func (flow *Flow) SetVerdict(v nfq.Verdict) {
	for _, packet := range flow.packets {
		packet.SetVerdict(v)
	}
}

func (flow *Flow) SetVerdictMark(v nfq.Verdict, mark uint32) {
	flow.mark = mark

	for _, packet := range flow.packets {
		packet.SetVerdictMark(v, mark)
	}
}

func (flow *Flow) IsDecided() bool {
	return flow.mark != 0
}

func (flow *Flow) Mark() uint32 {
	return flow.mark
}

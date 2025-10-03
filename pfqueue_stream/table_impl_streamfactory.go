package pfqueue_stream

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
)

func (table *Table) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	key := netFlow.String() + "|" + tcpFlow.String()
	flow := table.GetOrCreate(key)

	return flow
}

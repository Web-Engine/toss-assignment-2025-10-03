package pfqueue_stream

import (
	"sync"
	"toss/pfqueue_detector"
)

type Table struct {
	flowMap  sync.Map
	detector *pfqueue_detector.Detector
}

func NewTable(detector *pfqueue_detector.Detector) *Table {
	return &Table{
		detector: detector,
	}
}

func (table *Table) GetOrCreate(key string) *Flow {
	flow, _ := table.flowMap.LoadOrStore(key, NewFlow(key, table))
	return flow.(*Flow)
}

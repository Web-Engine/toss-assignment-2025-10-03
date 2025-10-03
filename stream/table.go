package stream

import (
	"sync"
	"toss/detector"
)

type Table struct {
	flowMap  sync.Map
	detector *detector.Detector
}

func NewTable(detector *detector.Detector) *Table {
	return &Table{
		detector: detector,
	}
}

func (table *Table) GetOrCreate(key string) *Flow {
	flow, _ := table.flowMap.LoadOrStore(key, NewFlow(key, table))
	return flow.(*Flow)
}

package main

import (
	"bufio"
	"strconv"
	"strings"
)

// EventType represents the event type of a trace entry.
type EventType int

const (
	REC  = iota // event: receive
	ENQ         // event: enqueue
	DEQ         // event: dequeue
	DROP        // event: drop
)

// TraceFlag represents a trace item flag.
type TraceFlag uint8

const (
	NONE = 0x0000
	ECN  = 0x0001 // Explicit Congestion Notification echo is enabled.
	PRI  = 0x0002 // Priority in IP header is enabled.
	CONA = 0x0004 // Congestion action.
	TCPF = 0x0008 // TCP fast start is used.
	ECNO = 0x0010 // Explicit Congestion Notification is on.
)

// TraceItem represents a trace file entry.
type TraceItem struct {
	Event          EventType
	Time           float64
	FromNode       int
	ToNode         int
	PacketType     string
	PacketSize     int
	Flags          int
	FlowID         int
	SourceAddr     Address
	DestAddr       Address
	SequenceNum    int
	UniquePacketID int
}

// Address holds the NS2 pseudo-address.
type Address struct {
	Address int
	Port    int
}

type JitterStat struct {
	FromNode   int
	ToNode     int
	PacketType string
	oldTime    float64         // 1
	oldSeq     float64         // 2
	Jitter     map[int]float64 // (sequence num, jitter)
}

type TraceStats struct {
	TotalEntries    int
	ReceivedPackets int
	DroppedPackets  int
	AvgHops         float32
	ActiveNodes     int
	TotalBandwidth  int
	NetworkTime     float64
}

func CalculateStats(traces []*TraceItem) (stat TraceStats) {
	var enq int
	var hop float32
	var nodes []int
	for _, trace := range traces {
		stat.TotalEntries++
		switch trace.Event {
		case REC:
			stat.ReceivedPackets++
		case DROP:
			stat.DroppedPackets++
		case ENQ:
			enq++
		case DEQ:
			// This allows us to accurately calculate hops
			if enq > 0 {
				enq--
				hop++
			}
		default:
			continue
		}
		if !hasNode(nodes, trace.FromNode) {
			nodes = append(nodes, trace.FromNode)
			stat.ActiveNodes++
		}
		if !hasNode(nodes, trace.ToNode) {
			nodes = append(nodes, trace.ToNode)
			stat.ActiveNodes++
		}

		stat.TotalBandwidth += trace.PacketSize
		if trace.Time > stat.NetworkTime {
			stat.NetworkTime = trace.Time
		}
	}
	stat.AvgHops = (hop / float32(stat.ReceivedPackets))
	return
}

func hasNode(nodes []int, node int) bool {
	for i := range nodes {
		if i == node {
			return true
		}
	}
	return false
}

func CalculateJitters(traces []*TraceItem) (s []*JitterStat) {
	for _, trace := range traces {
		if trace.Event != REC {
			continue
		}
		var js *JitterStat = nil
		index := -1
		for i, stat := range s {
			if stat.FromNode == trace.FromNode && stat.ToNode == trace.ToNode &&
				stat.PacketType == trace.PacketType {
				js = stat
				index = i
			}
		}

		if js == nil {
			js = &JitterStat{
				FromNode:   trace.FromNode,
				ToNode:     trace.ToNode,
				PacketType: trace.PacketType,
				oldTime:    0,
				oldSeq:     0,
				Jitter:     make(map[int]float64),
			}
		}

		diff := float64(trace.SequenceNum) - js.oldSeq
		if diff == 0 {
			diff = 1
		}
		if diff > 0 {
			js.Jitter[trace.SequenceNum] = ((trace.Time - js.oldTime) / diff)
			js.oldTime = float64(trace.Time)
			js.oldSeq = float64(trace.SequenceNum)
		}
		if index != -1 {
			s = removeJitter(s, index)
		}

		s = append(s, js)
	}
	return
}

func removeJitter(slice []*JitterStat, s int) []*JitterStat {
	return append(slice[:s], slice[s+1:]...)
}

// GetTracesFromBuffer takes an file buffer and converts it into a list of
// TraceItem.
func GetTracesFromBuffer(scanner *bufio.Scanner) ([]*TraceItem, error) {
	var traces []*TraceItem
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), " ")
		if len(parts) == 12 {
			ti := new(TraceItem)

			// Event
			switch parts[0] {
			case "r":
				ti.Event = REC
			case "+":
				ti.Event = ENQ
			case "-":
				ti.Event = DEQ
			case "d":
				ti.Event = DROP
			}

			// Time
			time, err := strconv.ParseFloat(parts[1], 64)
			if err != nil {
				return nil, err
			}
			ti.Time = time

			// FromNode
			var i int
			i, err = strconv.Atoi(parts[2])
			if err != nil {
				return nil, err
			}
			ti.FromNode = i

			// ToNode
			i, err = strconv.Atoi(parts[3])
			if err != nil {
				return nil, err
			}
			ti.ToNode = i

			// Packet type
			ti.PacketType = parts[4]

			// Packet size
			i, err = strconv.Atoi(parts[5])
			if err != nil {
				return nil, err
			}
			ti.PacketSize = i

			// TODO flags

			// Flow ID
			i, err = strconv.Atoi(parts[7])
			if err != nil {
				return nil, err
			}
			ti.FlowID = i

			// Source Address
			source := strings.Split(parts[8], ".")
			s1, _ := strconv.Atoi(source[0])
			s2, _ := strconv.Atoi(source[1])
			ti.SourceAddr = Address{s1, s2}

			// Destination Address
			dest := strings.Split(parts[9], ".")
			d1, _ := strconv.Atoi(dest[0])
			d2, _ := strconv.Atoi(dest[1])
			ti.DestAddr = Address{d1, d2}

			// Sequence Number
			i, err = strconv.Atoi(parts[10])
			if err != nil {
				return nil, err
			}
			ti.SequenceNum = i

			i, err = strconv.Atoi(parts[11])
			if err != nil {
				return nil, err
			}
			ti.UniquePacketID = i
			traces = append(traces, ti)
		}
	}

	return traces, nil
}

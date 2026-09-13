package main

import (
	"net"
	"sync/atomic"

	S "github.com/metacubex/sing/common/bufio"
	N "github.com/metacubex/sing/common/network"
)

const maxWireCounter = uint64(1<<53 - 1)

type monotonicCounter struct {
	value atomic.Uint64
}

func (counter *monotonicCounter) add(size int) {
	counter.count(int64(size))
}

func (counter *monotonicCounter) count(size int64) {
	if size <= 0 {
		return
	}
	increment := uint64(size)
	for {
		current := counter.value.Load()
		next := maxWireCounter
		if increment < maxWireCounter-current {
			next = current + increment
		}
		if counter.value.CompareAndSwap(current, next) {
			return
		}
	}
}

func (counter *monotonicCounter) increment() {
	counter.add(1)
}

type wireCounters struct {
	relayDownloadBytes     monotonicCounter
	relayUploadBytes       monotonicCounter
	carrierDownloadBytes   monotonicCounter
	carrierUploadBytes     monotonicCounter
	carrierDownloadPackets monotonicCounter
	carrierUploadPackets   monotonicCounter
	relayDownloadCopies    monotonicCounter
}

type wireSnapshot struct {
	RelayDownloadBytes     uint64 `json:"relayDownloadBytes"`
	RelayUploadBytes       uint64 `json:"relayUploadBytes"`
	CarrierDownloadBytes   uint64 `json:"carrierDownloadBytes"`
	CarrierUploadBytes     uint64 `json:"carrierUploadBytes"`
	CarrierDownloadPackets uint64 `json:"carrierDownloadPackets"`
	CarrierUploadPackets   uint64 `json:"carrierUploadPackets"`
	RelayDownloadCopies    uint64 `json:"relayDownloadCopies"`
}

func (counters *wireCounters) snapshot() wireSnapshot {
	return wireSnapshot{
		RelayDownloadBytes:     counters.relayDownloadBytes.value.Load(),
		RelayUploadBytes:       counters.relayUploadBytes.value.Load(),
		CarrierDownloadBytes:   counters.carrierDownloadBytes.value.Load(),
		CarrierUploadBytes:     counters.carrierUploadBytes.value.Load(),
		CarrierDownloadPackets: counters.carrierDownloadPackets.value.Load(),
		CarrierUploadPackets:   counters.carrierUploadPackets.value.Load(),
		RelayDownloadCopies:    counters.relayDownloadCopies.value.Load(),
	}
}

func newCountedConn(conn net.Conn, read, write *monotonicCounter) net.Conn {
	var readCounters, writeCounters []N.CountFunc
	if read != nil {
		readCounters = []N.CountFunc{read.count}
	}
	if write != nil {
		writeCounters = []N.CountFunc{write.count}
	}
	return S.NewCounterConn(conn, readCounters, writeCounters)
}

type countedPacketConn struct {
	net.PacketConn
	downloadBytes   *monotonicCounter
	uploadBytes     *monotonicCounter
	downloadPackets *monotonicCounter
	uploadPackets   *monotonicCounter
}

func (conn *countedPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	size, address, err := conn.PacketConn.ReadFrom(buffer)
	conn.downloadBytes.add(size)
	if size > 0 {
		conn.downloadPackets.increment()
	}
	return size, address, err
}

func (conn *countedPacketConn) WriteTo(buffer []byte, address net.Addr) (int, error) {
	size, err := conn.PacketConn.WriteTo(buffer, address)
	conn.uploadBytes.add(size)
	if size > 0 {
		conn.uploadPackets.increment()
	}
	return size, err
}

type pathStatus struct {
	PathID     string       `json:"pathId"`
	Generation uint64       `json:"generation"`
	Wire       wireSnapshot `json:"wire"`
}

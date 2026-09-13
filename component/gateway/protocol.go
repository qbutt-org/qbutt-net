// Package gateway owns authenticated reverse listeners, never torrent state.
package gateway

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"time"
)

const (
	Version                  = 2
	ALPN                     = "qbutt-gateway/2"
	MaxFrameBytes            = 16384
	MaxDatagramPayload       = 65507
	MaxDatagramFragmentBytes = 1024
	MaxDatagramFragments     = 64
	MaxIncompleteDatagrams   = 32
	MaxIncompleteBytes       = MaxIncompleteDatagrams * MaxDatagramPayload
	MaxRecentDatagrams       = 8192
	DatagramFragmentLifetime = 2 * time.Second
)

type Request struct {
	Version    int    `json:"v"`
	ID         uint64 `json:"id"`
	Method     string `json:"method"`
	Session    string `json:"session,omitempty"`
	Lease      string `json:"lease,omitempty"`
	Path       string `json:"path,omitempty"`
	Generation uint64 `json:"generation,omitempty"`
	Connection uint64 `json:"connection,omitempty"`
	TCP        bool   `json:"tcp,omitempty"`
	UDP        bool   `json:"udp,omitempty"`
	Port       uint16 `json:"port,omitempty"`
	TTLSeconds int    `json:"ttlSeconds,omitempty"`
}

type LeaseInfo struct {
	Session          string `json:"session"`
	Lease            string `json:"lease"`
	Path             string `json:"path"`
	Generation       uint64 `json:"generation"`
	Endpoint         string `json:"endpoint"`
	TCP              bool   `json:"tcp"`
	UDP              bool   `json:"udp"`
	ExpiresUnixMilli int64  `json:"expiresUnixMilli"`
}

// Accepted metadata originates exclusively from an authenticated gateway's
// accepted socket. The receiver must validate the active session/lease/generation.
type Accepted struct {
	LeaseInfo
	Connection uint64 `json:"connection"`
	Remote     string `json:"remote"`
}

type Response struct {
	Version         int            `json:"v"`
	ID              uint64         `json:"id,omitempty"`
	Error           string         `json:"error,omitempty"`
	Session         string         `json:"session,omitempty"`
	Lease           *LeaseInfo     `json:"lease,omitempty"`
	Accepted        *Accepted      `json:"accepted,omitempty"`
	Revoked         string         `json:"revoked,omitempty"`
	DatagramPayload int            `json:"datagramPayload,omitempty"`
	Datagrams       *DatagramStats `json:"datagrams,omitempty"`
}

// DatagramStats contains only aggregate payload and pressure counters. It
// deliberately excludes certificate identities, lease tokens and endpoints.
type DatagramStats struct {
	ToClientPackets    uint64 `json:"toClientPackets"`
	ToClientBytes      uint64 `json:"toClientBytes"`
	ToPublicPackets    uint64 `json:"toPublicPackets"`
	ToPublicBytes      uint64 `json:"toPublicBytes"`
	FragmentsSent      uint64 `json:"fragmentsSent"`
	FragmentsReceived  uint64 `json:"fragmentsReceived"`
	InvalidFragments   uint64 `json:"invalidFragments"`
	DuplicateFragments uint64 `json:"duplicateFragments"`
	ExpiredAssemblies  uint64 `json:"expiredAssemblies"`
	ReassemblyDrops    uint64 `json:"reassemblyDrops"`
	PolicyDrops        uint64 `json:"policyDrops"`
	PacketRateDrops    uint64 `json:"packetRateDrops"`
	ByteRateDrops      uint64 `json:"byteRateDrops"`
	QueueDrops         uint64 `json:"queueDrops"`
}

func ReadFrame(reader io.Reader, value any) error {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaxFrameBytes {
		return errors.New("frame_limit")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(reader, data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errors.New("invalid_frame")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid_frame")
	}
	return nil
}

func WriteFrame(writer io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil || len(data) > MaxFrameBytes {
		return errors.New("frame_limit")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	_, err = io.Copy(writer, io.MultiReader(bytes.NewReader(header[:]), bytes.NewReader(data)))
	return err
}

// Datagram is one original UDP payload, never a TCP frame. QUIC datagrams carry
// bounded fragments so an ordinary UDP datagram remains one datagram at each
// public endpoint even when it exceeds the peer's QUIC datagram size.
type Datagram struct {
	Lease      string
	Generation uint64
	Remote     netip.AddrPort
	Payload    []byte
}

type DatagramFragment struct {
	Datagram
	Message uint64
	Index   uint16
	Count   uint16
	Total   uint16
}

func EncodeDatagram(packet Datagram, message uint64) ([][]byte, error) {
	id, err := hex.DecodeString(packet.Lease)
	if err != nil || len(id) != 16 || packet.Generation == 0 || message == 0 || !packet.Remote.IsValid() || packet.Remote.Port() == 0 || len(packet.Payload) > MaxDatagramPayload {
		return nil, errors.New("invalid_datagram")
	}
	address := packet.Remote.Addr().Unmap()
	if address.IsUnspecified() || address.IsMulticast() || address.Zone() != "" {
		return nil, errors.New("invalid_endpoint")
	}
	count := (len(packet.Payload) + MaxDatagramFragmentBytes - 1) / MaxDatagramFragmentBytes
	if count == 0 {
		count = 1
	}
	if count > MaxDatagramFragments {
		return nil, errors.New("invalid_datagram")
	}
	result := make([][]byte, 0, count)
	for index := 0; index < count; index++ {
		start := index * MaxDatagramFragmentBytes
		end := start + MaxDatagramFragmentBytes
		if end > len(packet.Payload) {
			end = len(packet.Payload)
		}
		fragment := make([]byte, 0, 55+end-start)
		fragment = append(fragment, Version)
		fragment = append(fragment, id...)
		fragment = binary.BigEndian.AppendUint64(fragment, packet.Generation)
		fragment = binary.BigEndian.AppendUint64(fragment, message)
		fragment = binary.BigEndian.AppendUint16(fragment, uint16(index))
		fragment = binary.BigEndian.AppendUint16(fragment, uint16(count))
		fragment = binary.BigEndian.AppendUint16(fragment, uint16(len(packet.Payload)))
		if address.Is4() {
			fragment = append(fragment, 4)
		} else {
			fragment = append(fragment, 6)
		}
		fragment = append(fragment, address.AsSlice()...)
		fragment = binary.BigEndian.AppendUint16(fragment, packet.Remote.Port())
		result = append(result, append(fragment, packet.Payload[start:end]...))
	}
	return result, nil
}

func DecodeDatagram(data []byte) (DatagramFragment, error) {
	if len(data) < 46 || data[0] != Version {
		return DatagramFragment{}, errors.New("invalid_datagram")
	}
	size := 4
	if data[39] == 6 {
		size = 16
	} else if data[39] != 4 {
		return DatagramFragment{}, errors.New("invalid_datagram")
	}
	if len(data) < 42+size || len(data) > 42+size+MaxDatagramFragmentBytes {
		return DatagramFragment{}, errors.New("invalid_datagram")
	}
	address, ok := netip.AddrFromSlice(data[40 : 40+size])
	packet := DatagramFragment{Datagram: Datagram{Lease: hex.EncodeToString(data[1:17]), Generation: binary.BigEndian.Uint64(data[17:25]),
		Remote: netip.AddrPortFrom(address, binary.BigEndian.Uint16(data[40+size:42+size])), Payload: data[42+size:]},
		Message: binary.BigEndian.Uint64(data[25:33]), Index: binary.BigEndian.Uint16(data[33:35]),
		Count: binary.BigEndian.Uint16(data[35:37]), Total: binary.BigEndian.Uint16(data[37:39])}
	if !ok || packet.Generation == 0 || packet.Message == 0 || packet.Remote.Port() == 0 || address.IsUnspecified() || address.IsMulticast() ||
		packet.Count == 0 || packet.Count > MaxDatagramFragments || packet.Index >= packet.Count || int(packet.Total) > MaxDatagramPayload ||
		(packet.Count != uint16((int(packet.Total)+MaxDatagramFragmentBytes-1)/MaxDatagramFragmentBytes) && !(packet.Total == 0 && packet.Count == 1)) ||
		int(packet.Index)*MaxDatagramFragmentBytes+len(packet.Payload) > int(packet.Total) ||
		(packet.Index+1 < packet.Count && len(packet.Payload) != MaxDatagramFragmentBytes) ||
		(packet.Index+1 == packet.Count && int(packet.Index)*MaxDatagramFragmentBytes+len(packet.Payload) != int(packet.Total)) {
		return DatagramFragment{}, errors.New("invalid_datagram")
	}
	return packet, nil
}

type reassemblyKey struct {
	lease      string
	generation uint64
	message    uint64
}

type datagramAssembly struct {
	remote    netip.AddrPort
	total     uint16
	fragments [][]byte
	received  int
	deadline  time.Time
}

type ReassemblyStatus uint8

const (
	ReassemblyPending ReassemblyStatus = iota
	ReassemblyComplete
	ReassemblyDuplicate
	ReassemblyDropped
)

// Reassembler tolerates fragment reordering and duplicates while reserving the
// declared complete size up front. This makes incomplete peer input bounded.
type Reassembler struct {
	entries  map[reassemblyKey]*datagramAssembly
	complete map[reassemblyKey]time.Time
	bytes    int
}

func (r *Reassembler) Expire(now time.Time) int {
	expired := 0
	for key, entry := range r.entries {
		if !now.Before(entry.deadline) {
			r.bytes -= int(entry.total)
			delete(r.entries, key)
			expired++
		}
	}
	for key, deadline := range r.complete {
		if !now.Before(deadline) {
			delete(r.complete, key)
		}
	}
	return expired
}

func (r *Reassembler) Add(fragment DatagramFragment, now time.Time) (Datagram, ReassemblyStatus, int) {
	expired := r.Expire(now)
	if r.entries == nil {
		r.entries = make(map[reassemblyKey]*datagramAssembly)
		r.complete = make(map[reassemblyKey]time.Time)
	}
	key := reassemblyKey{lease: fragment.Lease, generation: fragment.Generation, message: fragment.Message}
	if _, exists := r.complete[key]; exists {
		return Datagram{}, ReassemblyDuplicate, expired
	}
	entry := r.entries[key]
	if entry == nil {
		if len(r.entries) >= MaxIncompleteDatagrams || r.bytes+int(fragment.Total) > MaxIncompleteBytes {
			return Datagram{}, ReassemblyDropped, expired
		}
		entry = &datagramAssembly{remote: fragment.Remote, total: fragment.Total,
			fragments: make([][]byte, fragment.Count), deadline: now.Add(DatagramFragmentLifetime)}
		r.entries[key] = entry
		r.bytes += int(fragment.Total)
	} else if entry.remote != fragment.Remote || entry.total != fragment.Total || len(entry.fragments) != int(fragment.Count) {
		r.bytes -= int(entry.total)
		delete(r.entries, key)
		return Datagram{}, ReassemblyDropped, expired
	}
	if entry.fragments[fragment.Index] != nil {
		return Datagram{}, ReassemblyDuplicate, expired
	}
	entry.fragments[fragment.Index] = append([]byte(nil), fragment.Payload...)
	entry.received++
	if entry.received != len(entry.fragments) {
		return Datagram{}, ReassemblyPending, expired
	}
	payload := make([]byte, 0, entry.total)
	for _, part := range entry.fragments {
		payload = append(payload, part...)
	}
	r.bytes -= int(entry.total)
	delete(r.entries, key)
	if len(r.complete) >= MaxRecentDatagrams {
		return Datagram{}, ReassemblyDropped, expired
	}
	r.complete[key] = now.Add(DatagramFragmentLifetime)
	return Datagram{Lease: fragment.Lease, Generation: fragment.Generation, Remote: fragment.Remote, Payload: payload}, ReassemblyComplete, expired
}

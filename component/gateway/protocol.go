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
)

const (
	Version            = 1
	ALPN               = "qbutt-gateway/1"
	MaxFrameBytes      = 16384
	MaxDatagramPayload = 1024
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
	Version         int        `json:"v"`
	ID              uint64     `json:"id,omitempty"`
	Error           string     `json:"error,omitempty"`
	Session         string     `json:"session,omitempty"`
	Lease           *LeaseInfo `json:"lease,omitempty"`
	Accepted        *Accepted  `json:"accepted,omitempty"`
	Revoked         string     `json:"revoked,omitempty"`
	DatagramPayload int        `json:"datagramPayload,omitempty"`
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

// Datagram is an RFC 9221 payload, never a TCP frame. Only numeric endpoints
// are admitted. Small packets need no second fragmentation or reliability layer.
type Datagram struct {
	Lease      string
	Generation uint64
	Remote     netip.AddrPort
	Payload    []byte
}

func EncodeDatagram(packet Datagram) ([]byte, error) {
	id, err := hex.DecodeString(packet.Lease)
	if err != nil || len(id) != 16 || packet.Generation == 0 || !packet.Remote.IsValid() || packet.Remote.Port() == 0 || len(packet.Payload) > MaxDatagramPayload {
		return nil, errors.New("invalid_datagram")
	}
	address := packet.Remote.Addr().Unmap()
	if address.IsUnspecified() || address.IsMulticast() || address.Zone() != "" {
		return nil, errors.New("invalid_endpoint")
	}
	result := make([]byte, 0, 44+len(packet.Payload))
	result = append(result, Version)
	result = append(result, id...)
	result = binary.BigEndian.AppendUint64(result, packet.Generation)
	if address.Is4() {
		result = append(result, 4)
	} else {
		result = append(result, 6)
	}
	result = append(result, address.AsSlice()...)
	result = binary.BigEndian.AppendUint16(result, packet.Remote.Port())
	return append(result, packet.Payload...), nil
}

func DecodeDatagram(data []byte) (Datagram, error) {
	if len(data) < 32 || data[0] != Version {
		return Datagram{}, errors.New("invalid_datagram")
	}
	size := 4
	if data[25] == 6 {
		size = 16
	} else if data[25] != 4 {
		return Datagram{}, errors.New("invalid_datagram")
	}
	if len(data) < 28+size || len(data) > 28+size+MaxDatagramPayload {
		return Datagram{}, errors.New("invalid_datagram")
	}
	address, ok := netip.AddrFromSlice(data[26 : 26+size])
	packet := Datagram{Lease: hex.EncodeToString(data[1:17]), Generation: binary.BigEndian.Uint64(data[17:25]),
		Remote: netip.AddrPortFrom(address, binary.BigEndian.Uint16(data[26+size:28+size])), Payload: data[28+size:]}
	if !ok || packet.Generation == 0 || packet.Remote.Port() == 0 || address.IsUnspecified() || address.IsMulticast() {
		return Datagram{}, errors.New("invalid_datagram")
	}
	return packet, nil
}

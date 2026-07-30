package hikws

import (
	"encoding/binary"
	"fmt"
)

// HikProtocol Constants
const (
	MsgTypeHello        byte = 0x01
	MsgTypeAuthRequest  byte = 0x02
	MsgTypeAuthResponse byte = 0x03
	MsgTypeKeyExchange  byte = 0x04
	MsgTypeSessionError byte = 0x05
	MsgTypeKeepAlive    byte = 0x06
	MsgTypeVideoData    byte = 0x40
	MsgTypeAudioData    byte = 0x41

	// EncryptFlag is carried in the high bit of the protocol type byte.
	EncryptFlag byte = 0x80
)

// ProtocolMessage is a parsed Hikvision protocol envelope. The 5-byte header
// is: 1-byte type (high bit = encrypted) + 4-byte big-endian length, followed
// by the payload. Several protocol messages may be concatenated in a single
// WebSocket binary frame; Remaining carries the bytes after this message.
type ProtocolMessage struct {
	Type      byte
	Encrypted bool
	Payload   []byte
	Remaining []byte
}

// PackMessage wraps the payload in the Hikvision 5-byte protocol header.
func PackMessage(msgType byte, data []byte) []byte {
	header := make([]byte, 5)
	header[0] = msgType
	binary.BigEndian.PutUint32(header[1:], uint32(len(data)))
	return append(header, data...)
}

// Unpack parses a Hikvision protocol envelope from data and returns the
// message plus any trailing bytes. It returns an error (instead of treating
// the data as raw video) when the header is incomplete or the declared
// payload length exceeds the available bytes, so callers can decide how to
// handle partial reads.
func Unpack(data []byte) (*ProtocolMessage, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("insufficient length for header")
	}

	typ := data[0]
	length := binary.BigEndian.Uint32(data[1:5])

	if uint32(len(data)) < 5+length {
		return nil, fmt.Errorf("insufficient length for payload")
	}

	return &ProtocolMessage{
		Type:      typ &^ EncryptFlag,
		Encrypted: typ&EncryptFlag != 0,
		Payload:   data[5 : 5+length],
		Remaining: data[5+length:],
	}, nil
}

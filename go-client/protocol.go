package hikws

import (
	"encoding/binary"
	"fmt"
)

// HikProtocol Constants
const (
	MsgTypeHello          byte = 0x01
	MsgTypeAuthRequest    byte = 0x02
	MsgTypeAuthResponse   byte = 0x03
	MsgTypeKeyExchange    byte = 0x04
	MsgTypeSessionError   byte = 0x05
	MsgTypeKeepAlive      byte = 0x06
	MsgTypeVideoData      byte = 0x40
	MsgTypeAudioData      byte = 0x41
)

var (
	SubTypeStreamStart byte = 0x01
	SubTypeStreamData  byte = 0x02
	SubTypeStreamEnd   byte = 0x03

	EncryptFlag byte = 0x80
)

// PackMessage wraps the payload in the Hikvision 5-byte protocol header
func PackMessage(msgType byte, data []byte) []byte {
	header := make([]byte, 5)
	header[0] = msgType
	binary.BigEndian.PutUint32(header[1:], uint32(len(data)))

	return append(header, data...)
}

// UnpackMessage expects data and returns (MsgType, Payload, RemainingData, Error)
func UnpackMessage(data []byte) (byte, []byte, []byte, error) {
	if len(data) < 5 {
		return 0, nil, data, fmt.Errorf("insufficient length for header")
	}

	msgType := data[0]
	length := binary.BigEndian.Uint32(data[1:5])

	if uint32(len(data)) < 5+length {
		return msgType, nil, data, fmt.Errorf("insufficient length for payload")
	}

	payload := data[5 : 5+length]
	remaining := data[5+length:]

	return msgType, payload, remaining, nil
}

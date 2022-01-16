package ike

import (
	"encoding/binary"
	"errors"
	"io"
)

//---------------------------------------------------------------------------------------
type ikeProtocolPayload struct {
	header    IKEProtocolPayloadHeader
	data      []byte
	pType     int
	readIndex int
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeProtocolPayload) GetType() int {
	return thisPt.pType
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeProtocolPayload) GetHeader() *IKEProtocolPayloadHeader {
	return &thisPt.header
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeProtocolPayload) GetBodyBuffer() []byte {
	return thisPt.data
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeProtocolPayload) Read(buffer []byte) (int, error) {
	if thisPt.readIndex >= len(thisPt.data) {
		return 0, io.EOF
	}

	rLen := len(buffer)
	if rLen+thisPt.readIndex > len(thisPt.data) {
		rLen = len(thisPt.data) - thisPt.readIndex
	}

	copy(buffer, thisPt.data[thisPt.readIndex:thisPt.readIndex+rLen])
	thisPt.readIndex += rLen
	return rLen, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeProtocolPayload) Seek(index int) {
	if index > len(thisPt.data) {
		index = len(thisPt.data)
	} else if index < 0 {
		index = 0
	}
	thisPt.readIndex = index
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeProtocolPayload) ReadRemind() int {
	return (len(thisPt.data) - thisPt.readIndex)
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeProtocolPayload) Write(p []byte) (n int, err error) {
	thisPt.data = append(thisPt.data, p...)
	thisPt.header.PayloadLen = uint16(len(thisPt.data)) + 4
	return len(p), nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeProtocolPayload) Serialize(w io.Writer) error {

	if err := binary.Write(w, binary.LittleEndian, &thisPt.header); err != nil {
		return err
	}

	if _, err := w.Write(thisPt.data); err != nil {
		return err
	}

	return nil
}

//---------------------------------------------------------------------------------------
func IKEProtocolReadPayload(pType int, r io.Reader) (IIKEPayload, error) {
	p := &ikeProtocolPayload{pType: pType}

	//read header
	if err := binary.Read(r, binary.LittleEndian, &p.header); err != nil {
		return nil, err
	}

	//read body
	if p.header.Reserved != 0 {
		return nil, errors.New("header reserved space is non-zero")
	}

	p.data = make([]byte, p.header.PayloadLen)
	if len, _ := r.Read(p.data); len != int(p.header.PayloadLen) {
		return nil, errors.New("invalid data length")
	}

	return p, nil
}

//---------------------------------------------------------------------------------------
func createProtocolPayload(pType int) IIKEPayload {
	p := &ikeProtocolPayload{pType: pType}
	return p
}

package ike

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/mohsenatigh/goke/gcrypto"
)

//---------------------------------------------------------------------------------------
type ikeProtocolPacket struct {
	header           IKEProtocolHeader
	payloads         []IIKEPayload
	payloadFactory   IIKEPacketPayloadFactory
	payloadDissector IIKEPacketPayloadDissector
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeProtocolPacket) getBodyLen() int {
	total := 0
	for _, p := range thisPt.payloads {
		total += int(p.GetHeader().PayloadLen)
	}
	return total
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeProtocolPacket) serializeBody(w io.Writer) error {

	pLen := len(thisPt.payloads)
	if pLen == 0 {
		return nil
	}

	//adjust next header and serialize
	for i := 0; i < pLen; i++ {
		if i < pLen-1 {
			thisPt.payloads[i].GetHeader().NextPayload = uint8(thisPt.payloads[i+1].GetType())
		} else {
			thisPt.payloads[i].GetHeader().NextPayload = 0
		}

		if err := thisPt.payloads[i].Serialize(w); err != nil {
			return err
		}
	}
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeProtocolPacket) loadPayload(r io.Reader) error {
	pType := thisPt.header.NPayload
	for pType != 0 {
		payload, err := IKEProtocolReadPayload(int(pType), r)
		if err != nil {
			return err
		}
		pType = payload.GetHeader().NextPayload
		thisPt.payloads = append(thisPt.payloads, payload)
	}
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeProtocolPacket) Load(r io.Reader) error {

	//clear current payloads
	thisPt.payloads = []IIKEPayload{}

	//read header
	if err := binary.Read(r, binary.BigEndian, &thisPt.header); err != nil {
		return err
	}

	if thisPt.header.Version != 0x20 {
		return errors.New("invalid IKE packet")
	}

	//read payloads
	return thisPt.loadPayload(r)
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeProtocolPacket) GetHeader() *IKEProtocolHeader {
	return &thisPt.header
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeProtocolPacket) GetPayload(code int, index int) IIKEPayload {
	pIndex := 0
	for _, p := range thisPt.payloads {
		if p.GetType() == code {
			if pIndex == index {
				p.Seek(0)
				return p
			} else {
				pIndex++
			}
		}
	}
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeProtocolPacket) HasError() (bool, int) {
	for _, p := range thisPt.payloads {
		if p.GetType() == IKEProtocolPayloadType_N {
			header := IKEProtocolNotifyStaticHeader{}
			if err := binary.Read(p, binary.BigEndian, &header); err != nil {
				return true, -1
			}

			if header.NotifyMessageType < IKEProtocolNotifyCodes_INITIAL_CONTACT {
				return true, int(header.NotifyMessageType)
			}
		}
	}
	return false, -1
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeProtocolPacket) CreateFreePayload(code int) IIKEPayload {
	payload := createProtocolPayload(code)
	return payload
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeProtocolPacket) CreatePayload(code int) IIKEPayload {
	payload := thisPt.CreateFreePayload(code)
	thisPt.payloads = append(thisPt.payloads, payload)
	return payload
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeProtocolPacket) Dump() string {
	res := ""
	res = fmt.Sprintf("header : %v \n", thisPt.header)
	for _, p := range thisPt.payloads {
		res += fmt.Sprintf("\ttype : %d  header : %v \n", p.GetType(), p.GetHeader())
	}
	return res
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeProtocolPacket) Serialize(w io.Writer) error {
	thisPt.header.Version = 0x20

	//calculate length
	thisPt.header.Length = uint32(thisPt.getBodyLen()) + IKEProtocolHeaderSize
	thisPt.header.NPayload = 0

	//get type
	if len(thisPt.payloads) > 0 {
		thisPt.header.NPayload = uint8(thisPt.payloads[0].GetType())
	}

	//write header
	if err := binary.Write(w, binary.BigEndian, &thisPt.header); err != nil {
		return err
	}

	//
	return thisPt.serializeBody(w)
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeProtocolPacket) checkHMAC(payload IIKEPayload, auth gcrypto.IGCryptoHMAC) bool {
	payloadData := payload.GetBodyBuffer()

	if len(payloadData) < auth.GetLen() {
		return false
	}

	//
	hmac := payloadData[len(payloadData)-auth.GetLen():]
	body := payloadData[0 : len(payloadData)-auth.GetLen()]

	//serialize herader
	hBuffer := bytes.NewBuffer(nil)
	if err := binary.Write(hBuffer, binary.BigEndian, &thisPt.header); err != nil {
		return false
	}

	if err := auth.Start(); err != nil {
		return false
	}

	//write header buffer
	auth.Write(hBuffer.Bytes())
	auth.Write(body)

	cHmac := auth.Final()

	return bytes.Equal(cHmac, hmac)
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeProtocolPacket) Decrypt(encrypt gcrypto.IGCryptoCipher, auth gcrypto.IGCryptoHMAC) (IIKEPacket, error) {

	//find encrypted payload
	payload := thisPt.GetPayload(IKEProtocolPayloadType_E, 0)
	if payload == nil {
		return nil, errors.New("can not find any encrypted payload")
	}

	//
	payloadData := payload.GetBodyBuffer()

	//check hmac
	if !thisPt.checkHMAC(payload, auth) {
		return nil, errors.New("invalid packet checksum")
	}

	//
	encControlLen := (encrypt.GetAlg().BlockSize() + auth.GetLen())
	if len(payloadData) < encControlLen {
		return nil, errors.New("invalid encrypted payload")
	}

	//read IV
	iv := payloadData[0:encrypt.GetAlg().BlockSize()]
	body := payloadData[encrypt.GetAlg().BlockSize() : len(payloadData)-encControlLen]
	if len(body) == 0 {
		return nil, errors.New("invalid encrypted payload")
	}

	//decrypt body
	dBuffer := make([]byte, len(body))
	if err := encrypt.Decrypt(body, dBuffer, iv); err != nil {
		return nil, err
	}

	//create final packet
	packet := &ikeProtocolPacket{}
	packet.header = thisPt.header
	packet.header.NPayload = payload.GetHeader().NextPayload

	reader := bytes.NewReader(dBuffer)
	if err := packet.loadPayload(reader); err != nil {
		return nil, err
	}
	return packet, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeProtocolPacket) Encrypt(w io.Writer, encrypt gcrypto.IGCryptoCipher, auth gcrypto.IGCryptoHMAC) error {

	//To many memory copies is for creating a clean code, anyway, the main performance bottleneck is encryption, not memory copy
	//HEADER | ENC-PAYLOAD-HEADER | IV{N} | BODY{N} | PAD {N} | PADLEN{1} |

	//get IV
	iv := encrypt.GetIV()

	//
	if len(thisPt.payloads) == 0 {
		return errors.New("invalid packet for encryption")
	}

	//make body and encrypt it
	bodyTempBuffer := bytes.NewBuffer(nil)
	if err := thisPt.serializeBody(bodyTempBuffer); err != nil {
		return err
	}

	//calculate body PAD len and write PAD
	padLen := encrypt.GetPadLen(bodyTempBuffer.Len() + 1)
	bodyTempBuffer.Write(make([]byte, padLen))
	bodyTempBuffer.WriteByte(byte(padLen))

	//encrypt the body
	encBuffer := make([]byte, bodyTempBuffer.Len())
	if err := encrypt.Encrypt(bodyTempBuffer.Bytes(), encBuffer, iv); err != nil {
		return err
	}

	//serialize encryption header
	payloadBuffer := bytes.NewBuffer(nil)

	eHeader := IKEProtocolHeader{}
	eHeader = thisPt.header
	eHeader.NPayload = IKEProtocolPayloadType_E
	eHeader.Version = 0x20
	eHeader.Length += IKEProtocolHeaderSize
	eHeader.Length += IKEProtocolPayloadHeaderSize
	eHeader.Length += uint32(len(iv))
	eHeader.Length += uint32(len(encBuffer))
	eHeader.Length += uint32(auth.GetLen())
	if err := binary.Write(payloadBuffer, binary.BigEndian, &eHeader); err != nil {
		return err
	}

	//serialize payload header
	epHeader := IKEProtocolPayloadHeader{}
	epHeader.PayloadLen = uint16(eHeader.Length - IKEProtocolHeaderSize)
	epHeader.NextPayload = uint8(thisPt.payloads[0].GetType())
	if err := binary.Write(payloadBuffer, binary.BigEndian, &epHeader); err != nil {
		return err
	}

	//serialize iv
	if _, err := payloadBuffer.Write(iv); err != nil {
		return err
	}

	//add encrypted body
	if _, err := payloadBuffer.Write(encBuffer); err != nil {
		return err
	}

	//add authentication
	hMac, err := auth.GetHMAC(payloadBuffer.Bytes())
	if err != nil {
		return err
	}

	if _, err := payloadBuffer.Write(hMac); err != nil {
		return err
	}

	if _, err := w.Write(payloadBuffer.Bytes()); err != nil {
		return err
	}

	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeProtocolPacket) GetPayloadDissector() IIKEPacketPayloadDissector {
	return thisPt.payloadDissector
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeProtocolPacket) GetPayloadFactory() IIKEPacketPayloadFactory {
	return thisPt.payloadFactory
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeProtocolPacket) SetSequence(flag uint8, seq uint32) {
	thisPt.header.Id = seq
	thisPt.header.Flags = flag
}

//---------------------------------------------------------------------------------------
func createIKEPacket(r io.Reader, pType uint8) (IIKEPacket, error) {
	packet := &ikeProtocolPacket{}
	if r != nil {
		if err := packet.Load(r); err != nil {
			return nil, err
		}
	} else {
		packet.header.ExType = pType
	}

	packet.payloadDissector = createPayloadDissector(packet)
	packet.payloadFactory = createPayloadFactory(packet)
	return packet, nil
}

//---------------------------------------------------------------------------------------

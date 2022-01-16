package ike

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type ikePacketPayloadDissector struct {
	packet IIKEPacket
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePacketPayloadDissector) readID(code int) (IKEPayloadIDInfo, error) {
	info := IKEPayloadIDInfo{}
	payload := thisPt.packet.GetPayload(code, 0)
	if payload == nil {
		return info, errors.New("can not find id payload")
	}

	//read header
	ikeHeader := IKEProtocolIDHeader{}
	if err := binary.Read(payload, binary.LittleEndian, &ikeHeader); err != nil {
		return info, err
	}

	info.IDType = ikeHeader.IDType
	info.IDData = make([]byte, payload.GetHeader().PayloadLen)
	if l, _ := payload.Read(info.IDData); l > 0 {
		return info, nil
	}
	return info, errors.New("invalid id payload")
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePacketPayloadDissector) haveNotify(code int) IIKEPayload {

	for i := 0; ; i++ {
		payload := thisPt.packet.GetPayload(IKEProtocolPayloadType_N, i)
		if payload == nil {
			break
		}
		nHeader := IKEProtocolNotifyStaticHeader{}
		if err := binary.Read(payload, binary.LittleEndian, &nHeader); err != nil {
			continue
		}
		if nHeader.NotifyMessageType == uint16(code) {
			return payload
		}
	}
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePacketPayloadDissector) dissectProposalPayload(payload IIKEPayload) ([]IKEPayloadProposalInfo, error) {
	outList := []IKEPayloadProposalInfo{}

	readTransform := func(payload IIKEPayload, info *IKEPayloadProposalInfo) error {
		transformHeader := IKEProtocolProposalTransformHeader{}
		if err := binary.Read(payload, binary.LittleEndian, &transformHeader); err != nil {
			return err
		}

		switch transformHeader.TransformType {
		case IKEProtocolTransformType_ENCR:
			{
				var keyLen uint16
				info.EncryptionAlg = int(transformHeader.TransformID)
				if err := binary.Read(payload, binary.LittleEndian, &keyLen); err != nil {
					return err
				}
				info.EncryptionAlgKeyLen = int(keyLen)
			}
		case IKEProtocolTransformType_PRF:
			{
				info.Prf = int(transformHeader.TransformID)
			}
		case IKEProtocolTransformType_INTEG:
			{
				info.IntegrityAlg = int(transformHeader.TransformID)
			}
		case IKEProtocolTransformType_DH:
			{
				info.DH = int(transformHeader.TransformID)
			}
		case IKEProtocolTransformType_ESN:
			{
				info.ESN = int(transformHeader.TransformID)
			}
		}
		return nil
	}

	//read proposals
	for {
		info := IKEPayloadProposalInfo{}
		proposalHeader := IKEProtocolProposalHeader{}

		if err := binary.Read(payload, binary.LittleEndian, &proposalHeader); err != nil {
			break
		}

		for i := 0; i < int(proposalHeader.Transform); i++ {
			if err := readTransform(payload, &info); err != nil {
				return nil, err
			}
		}

		outList = append(outList, info)
	}
	return outList, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePacketPayloadDissector) GetCertRequest() ([][]byte, error) {

	certType := [1]byte{}

	const SHA1_LEN = 20
	certHashList := [][]byte{}

	payload := thisPt.packet.GetPayload(IKEProtocolPayloadType_CERTREQ, 0)
	if payload == nil {
		return nil, errors.New("can not find cert request payload")
	}

	if len, err := payload.Read(certType[:]); len != 1 || err != nil {
		return nil, err
	}

	if certType[0] != 0x4 {
		return nil, errors.New("invalid certificate type")
	}

	for {
		hash := [SHA1_LEN]byte{}
		if len, err := payload.Read(hash[:1]); len != SHA1_LEN || err != nil {
			break
		}
		certHashList = append(certHashList, hash[:])
	}

	return certHashList, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePacketPayloadDissector) GetCert() ([]byte, error) {
	certType := [1]byte{}
	payload := thisPt.packet.GetPayload(IKEProtocolPayloadType_CERT, 0)
	if payload == nil {
		return nil, errors.New("can not find cert payload")
	}

	if len, err := payload.Read(certType[:]); len != 1 || err != nil {
		return nil, err
	}

	if certType[0] != 0x4 {
		return nil, errors.New("invalid certificate type")
	}

	cert := make([]byte, 4096)
	certLen, err := payload.Read(cert)
	if err != nil {
		return nil, err
	}
	return cert[0:certLen], nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePacketPayloadDissector) GetVendorInfo() ([]byte, error) {
	payload := thisPt.packet.GetPayload(IKEProtocolPayloadType_V, 0)
	if payload == nil {
		return nil, errors.New("can not find vendor payload")
	}
	return payload.GetBodyBuffer(), nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePacketPayloadDissector) GetPhase1Proposal() ([]IKEPayloadProposalInfo, error) {
	payload := thisPt.packet.GetPayload(IKEProtocolPayloadType_SA, 0)
	if payload == nil {
		return nil, errors.New("can not find SA payload")
	}
	return thisPt.dissectProposalPayload(payload)
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePacketPayloadDissector) GetNonce() ([]byte, error) {
	payload := thisPt.packet.GetPayload(IKEProtocolPayloadType_V, 0)
	if payload == nil {
		return nil, errors.New("can not find nonce payload")
	}
	return payload.GetBodyBuffer(), nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePacketPayloadDissector) GetDH() ([]byte, int, error) {
	//read payload
	payload := thisPt.packet.GetPayload(IKEProtocolPayloadType_KE, 0)
	if payload == nil {
		return nil, 0, errors.New("can not find DH payload")
	}

	//read header
	header := IKEProtocolDHKeyHeader{}
	if err := binary.Read(payload, binary.LittleEndian, &header); err != nil {
		return nil, 0, err
	}

	//read public key
	pubKey := make([]byte, 16000)
	len, _ := payload.Read(pubKey)

	return pubKey[0:len], int(header.Group), nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePacketPayloadDissector) GetHaveFragmentSupport() bool {
	return (thisPt.haveNotify(IKEProtocolNotifyCodes_FRAGMENT_SUPPORTED) != nil)
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePacketPayloadDissector) GetHaveTransportSupport() bool {
	return (thisPt.haveNotify(IKEProtocolNotifyCodes_USE_TRANSPORT_MODE) != nil)
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePacketPayloadDissector) GetNAT(source bool) ([]byte, error) {
	var payload IIKEPayload
	if source {
		payload = thisPt.haveNotify(IKEProtocolNotifyCodes_NAT_DETECTION_SOURCE_IP)
	} else {
		payload = thisPt.haveNotify(IKEProtocolNotifyCodes_NAT_DETECTION_DESTINATION_IP)
	}

	if payload == nil {
		return nil, errors.New("can not find NAT payload")
	}

	hash := [64]byte{}
	hLen, _ := payload.Read(hash[:])
	return hash[:hLen], nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePacketPayloadDissector) GetPhase2Proposal() ([]IKEPayloadProposalInfo, error) {
	payload := thisPt.packet.GetPayload(IKEProtocolPayloadType_SA, 0)
	if payload == nil {
		return nil, errors.New("can not find SA payload")
	}
	return thisPt.dissectProposalPayload(payload)
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePacketPayloadDissector) GetTrafficSelector(initiator bool) (IKEPayloadTrafficSelectorInfo, error) {
	var payload IIKEPayload
	info := IKEPayloadTrafficSelectorInfo{}

	if initiator {
		payload = thisPt.packet.GetPayload(IKEProtocolPayloadType_TSI, 0)
	} else {
		payload = thisPt.packet.GetPayload(IKEProtocolPayloadType_TSR, 0)
	}

	readIP := func(payload IIKEPayload, buffer []byte) error {
		if rLen, _ := payload.Read(buffer); rLen != len(buffer) {
			return errors.New("invalid TS payload format")
		}
		return nil
	}

	for {
		//read static header
		policy := IKEPayloadTrafficPolicy{}
		header := IKEProtocolTrafficSelectorItemStaticHeader{}
		if err := binary.Read(payload, binary.LittleEndian, &header); err != nil {
			break
		}

		//read info
		policy.Type = header.TSType
		policy.Protocol = header.IPProto
		policy.StartPort = header.StartPort
		policy.EndPort = header.EndPort
		if header.Len == 16 {
			policy.StartAddress = make([]byte, 4)
			policy.EndAddress = make([]byte, 4)
		} else {
			policy.StartAddress = make([]byte, 16)
			policy.EndAddress = make([]byte, 16)
		}

		if err := readIP(payload, policy.StartAddress); err != nil {
			return info, err
		}

		if err := readIP(payload, policy.EndAddress); err != nil {
			return info, err
		}

		info.TrafficPolicy = append(info.TrafficPolicy, policy)
	}

	return info, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePacketPayloadDissector) ValidateAuth(info *IKEPayloadAuthInfo) error {

	payload := thisPt.packet.GetPayload(IKEProtocolPayloadType_AUTH, 0)
	if payload == nil {
		return errors.New("can not find Auth payload")
	}

	//read header
	authStaticHeader := IKEProtocolAuthPayloadHeader{}
	if err := binary.Read(payload, binary.LittleEndian, &authStaticHeader); err != nil {
		return err
	}

	//read message
	msgBuffer := make([]byte, payload.GetHeader().PayloadLen)
	if len, _ := payload.Read(msgBuffer); len > 0 {
		msgBuffer = msgBuffer[0:len]
	} else {
		return errors.New("invalid authentication payload")
	}

	//create message buffer
	buffer := bytes.NewBuffer(nil)
	buffer.Write(info.PrevMessage)
	buffer.Write(info.Nonce)
	prfBuf, err := info.PRF.GetHMAC(info.ID)
	if err != nil {
		return err
	}
	buffer.Write(prfBuf)

	//
	if authStaticHeader.AuthenticationType == IKEProtocolAuthType_RSA {
		if err := info.PublicKey.Verify(buffer.Bytes(), msgBuffer); err != nil {
			return err
		}
	} else if authStaticHeader.AuthenticationType == IKEProtocolAuthType_PSK {
		info.PRF.SetKey(info.PSK)
		p2Prfkey, err := info.PRF.GetHMAC([]byte(IKEPROTOCOL_PSK_PAD))
		if err != nil {
			return err
		}
		info.PRF.SetKey(p2Prfkey)
		data, err := info.PRF.GetHMAC(buffer.Bytes())
		if err != nil {
			return err
		}
		if !bytes.Equal(data, msgBuffer) {
			return errors.New("authentication failed")
		}
	} else {
		return errors.New("invalid auth type")
	}

	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePacketPayloadDissector) GetDelete() (IKEPayloadDeleteInfo, error) {
	const max_DELETE_SPI = 10
	const max_SPI_LEN = 8

	delInfo := IKEPayloadDeleteInfo{}

	payload := thisPt.packet.GetPayload(IKEProtocolPayloadType_D, 0)
	if payload == nil {
		return delInfo, errors.New("can not find delete payload")
	}

	//read header
	header := IKEProtocolDeleteHeader{}
	if err := binary.Read(payload, binary.LittleEndian, &header); err != nil {
		return delInfo, err
	}

	//
	if header.NumSPI > max_DELETE_SPI || header.SPISize > max_SPI_LEN {
		return delInfo, errors.New("invalid delete header")
	}

	//
	for i := 0; i < int(header.NumSPI); i++ {
		spiBuffer := make([]byte, header.SPISize)
		if l, _ := payload.Read(spiBuffer); l != int(header.SPISize) {
			return delInfo, errors.New("invalid delete payload")
		}
		delInfo.SPIList = append(delInfo.SPIList, spiBuffer)
	}

	delInfo.ProtocolID = header.ProtocolId
	return delInfo, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePacketPayloadDissector) GetInitiatorID() (IKEPayloadIDInfo, error) {
	return thisPt.readID(IKEProtocolPayloadType_IDi)
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePacketPayloadDissector) GetResponderID() (IKEPayloadIDInfo, error) {
	return thisPt.readID(IKEProtocolPayloadType_IDr)
}

//---------------------------------------------------------------------------------------
func createPayloadDissector(packet IIKEPacket) IIKEPacketPayloadDissector {
	return &ikePacketPayloadDissector{
		packet: packet,
	}
}

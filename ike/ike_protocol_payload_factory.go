package ike

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"

	"github.com/mohsenatigh/goke/gcrypto"
)

type ikePayloadFactory struct {
	packet IIKEPacket
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePayloadFactory) createIdPayload(pType int, info *IKEPayloadIDInfo) (IIKEPayload, error) {
	header := IKEProtocolIDHeader{}
	header.IDType = info.IDType
	payload := thisPt.packet.CreatePayload(pType)
	binary.Write(payload, binary.BigEndian, &header)
	payload.Write(info.IDData)
	return payload, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePayloadFactory) createProposalPayload(list []IKEPayloadProposalInfo, id uint8) (IIKEPayload, error) {

	//function for creating transform payload
	createTransformPayload := func(tType uint8, id uint16, keyLen uint16) IIKEPayload {

		payload := thisPt.packet.CreateFreePayload(IKEProtocolPayloadType_T)

		//write transform header
		transformHeader := IKEProtocolProposalTransformHeader{
			TransformID:   id,
			TransformType: tType,
			Reserved:      0}
		binary.Write(payload, binary.BigEndian, &transformHeader)

		//for enc-key  add key attributes
		if tType == IKEProtocolTransformType_ENCR {
			keyInfo := IKEProtocolProposalTransformKeyInfo{
				KeyLen: keyLen,
				Type:   0x800e,
			}
			binary.Write(payload, binary.BigEndian, &keyInfo)
		}

		//create payload
		return payload
	}

	//
	createProposal := func(index uint8, proposal *IKEPayloadProposalInfo) IIKEPayload {

		payload := thisPt.packet.CreateFreePayload(IKEProtocolPayloadType_P)

		//create and write main header
		pHeader := IKEProtocolProposalHeader{
			PNumber:   index,
			Transform: 4,
			ID:        id,
			SPISize:   0,
		}
		binary.Write(payload, binary.BigEndian, &pHeader)

		//create enc transform
		payload.Write(createTransformPayload(
			IKEProtocolTransformType_ENCR,
			uint16(proposal.EncryptionAlg),
			uint16(proposal.EncryptionAlgKeyLen)).GetBodyBuffer())

		//
		payload.Write(createTransformPayload(
			IKEProtocolTransformType_INTEG,
			uint16(proposal.IntegrityAlg),
			0).GetBodyBuffer())

		if id == IKEProtocolProposalHeaderID_IKE {
			//
			payload.Write(createTransformPayload(
				IKEProtocolTransformType_PRF,
				uint16(proposal.Prf),
				0).GetBodyBuffer())

			//
			payload.Write(createTransformPayload(
				IKEProtocolTransformType_DH,
				uint16(proposal.DH),
				0).GetBodyBuffer())
		} else {
			payload.Write(createTransformPayload(
				IKEProtocolTransformType_ESN,
				uint16(proposal.ESN),
				0).GetBodyBuffer())
		}

		//
		return payload
	}

	payload := thisPt.packet.CreatePayload(IKEProtocolPayloadType_SA)
	for i, p := range list {
		proposal := createProposal(uint8(i+1), &p)
		payload.Write(proposal.GetBodyBuffer())
	}
	return payload, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePayloadFactory) CreateNotify(protocolId uint8, code uint16, data []byte) (IIKEPayload, error) {

	header := IKEProtocolNotifyStaticHeader{
		ProtocolID:        protocolId,
		SpiSize:           0,
		NotifyMessageType: code,
	}
	payload := thisPt.packet.CreatePayload(IKEProtocolPayloadType_N)
	binary.Write(payload, binary.BigEndian, &header)
	if data != nil {
		payload.Write(data)
	}
	return payload, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePayloadFactory) CreateCertRequest(cert gcrypto.IGCryptoRSA, ca gcrypto.IGCryptoRSA) (IIKEPayload, error) {

	payload := thisPt.packet.CreatePayload(IKEProtocolPayloadType_CERTREQ)
	//write cert type
	payload.Write([]byte{0x04})
	if cert != nil {
		payload.Write(cert.GetCertSubjectInfoKeyID())
	}
	if ca != nil {
		payload.Write(ca.GetCertSubjectInfoKeyID())
	}
	return payload, nil
}

//---------------------------------------------------------------------------------------

func (thisPt *ikePayloadFactory) CreateCert(cert gcrypto.IGCryptoRSA) (IIKEPayload, error) {
	payload := thisPt.packet.CreatePayload(IKEProtocolPayloadType_CERT)

	//write cert type
	payload.Write([]byte{0x04})
	payload.Write(cert.GetDER())
	return payload, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePayloadFactory) CreateVendorInfo(vendorInfo []byte) (IIKEPayload, error) {
	payload := thisPt.packet.CreatePayload(IKEProtocolPayloadType_V)
	payload.Write(vendorInfo)
	return payload, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePayloadFactory) CreatePhase1Proposal(list []IKEPayloadProposalInfo) (IIKEPayload, error) {
	return thisPt.createProposalPayload(list, IKEProtocolProposalHeaderID_IKE)
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePayloadFactory) CreateNonce(data []byte) (IIKEPayload, error) {
	payload := thisPt.packet.CreatePayload(IKEProtocolPayloadType_NIR)
	payload.Write(data)
	return payload, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePayloadFactory) CreateConfigurationReply(v4 *IKEPayloadConfigurationInfo, v6 *IKEPayloadConfigurationInfo) (IIKEPayload, error) {
	payload := thisPt.packet.CreatePayload(IKEProtocolPayloadType_CP)

	addAttribute := func(w io.Writer, attType uint16, ip net.IP) {
		header := IKEProtocolConfigurationAttributeHeader{}
		header.AttType = attType
		header.Length = uint16(len(ip))
		binary.Write(w, binary.BigEndian, &header)
	}

	if v4.HaveIp {
		addAttribute(payload, IKEProtocolConfigurationAttributeType_IPv4, v4.IP)
	}

	if v4.HaveDNS {
		addAttribute(payload, IKEProtocolConfigurationAttributeType_DNS, v4.DNS1)
		addAttribute(payload, IKEProtocolConfigurationAttributeType_DNS, v4.DNS2)
	}

	if v4.HaveMask {
		addAttribute(payload, IKEProtocolConfigurationAttributeType_NetMask, v4.Mask)
	}

	if v4.HaveServer {
		addAttribute(payload, IKEProtocolConfigurationAttributeType_IPv4Server, v4.Server)
	}

	if v6.HaveIp {
		addAttribute(payload, IKEProtocolConfigurationAttributeType_IPv6, v6.IP)
	}

	if v6.HaveDNS {
		addAttribute(payload, IKEProtocolConfigurationAttributeType_IPv6DNS, v6.DNS1)
		addAttribute(payload, IKEProtocolConfigurationAttributeType_IPv6DNS, v6.DNS2)
	}

	if v6.HaveMask {
		addAttribute(payload, IKEProtocolConfigurationAttributeType_Ipv6Subnet, v6.Mask)
	}

	if v6.HaveServer {
		addAttribute(payload, IKEProtocolConfigurationAttributeType_IPv6Server, v6.Server)
	}
	return payload, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePayloadFactory) CreateDH(dh gcrypto.IGCryptoDH) (IIKEPayload, error) {
	header := IKEProtocolDHKeyHeader{}
	header.Group = uint16(dh.GetGroup())
	header.Res = 0

	payload := thisPt.packet.CreatePayload(IKEProtocolPayloadType_KE)
	binary.Write(payload, binary.BigEndian, &header)

	pKey, err := dh.GetPublicKey()
	if err != nil {
		return nil, err
	}
	payload.Write(pKey)
	return payload, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePayloadFactory) CreateFragmentSupport() (IIKEPayload, error) {
	return thisPt.CreateNotify(0, IKEProtocolNotifyCodes_FRAGMENT_SUPPORTED, nil)
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePayloadFactory) CreateTransportSupport() (IIKEPayload, error) {
	return thisPt.CreateNotify(0, IKEProtocolNotifyCodes_USE_TRANSPORT_MODE, nil)
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePayloadFactory) CreateNAT(info *IKEPayloadNatInfo) (IIKEPayload, error) {

	code := IKEProtocolNotifyCodes_NAT_DETECTION_SOURCE_IP
	if !info.Src {
		code = IKEProtocolNotifyCodes_NAT_DETECTION_DESTINATION_IP
	}

	if err := info.Hash.Start(); err != nil {
		return nil, err
	}

	info.Hash.Write(info.SPI[:])
	info.Hash.Write(info.SPR[:])
	info.Hash.Write(info.IPI)
	info.Hash.Write(info.IPR)

	return thisPt.CreateNotify(1, uint16(code), info.Hash.Final())
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePayloadFactory) CreatePhase2Proposal(list []IKEPayloadProposalInfo) (IIKEPayload, error) {
	return thisPt.createProposalPayload(list, IKEProtocolProposalHeaderID_ESP)
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePayloadFactory) CreateTrafficSelector(info *IKEPayloadTrafficSelectorInfo) (IIKEPayload, error) {

	tsType := IKEProtocolPayloadType_TSI
	if !info.Initiator {
		tsType = IKEProtocolPayloadType_TSR
	}

	payload := thisPt.packet.CreatePayload(tsType)

	//write header
	header := IKEProtocolTrafficSelectorHeader{}
	header.TSCount = uint8(len(info.TrafficPolicy))
	binary.Write(payload, binary.BigEndian, &header)

	//write selectors
	for _, ts := range info.TrafficPolicy {
		header := IKEProtocolTrafficSelectorItemStaticHeader{}
		header.TSType = ts.Type
		header.StartPort = ts.StartPort
		header.EndPort = ts.EndPort
		header.IPProto = ts.Protocol
		header.Len = 8 //sizeof(IKEProtocolTrafficSelectorItemStaticHeader)
		if ts.Type == IKEProtocolTrafficSelectorIPVersion_V4 {
			header.Len += 8
		} else {
			header.Len += 32
		}

		//write selector header
		binary.Write(payload, binary.BigEndian, &header)

		//write IP addressess
		payload.Write(ts.StartAddress)
		payload.Write(ts.EndAddress)
	}

	return payload, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePayloadFactory) CreateAuth(info *IKEPayloadAuthInfo) (IIKEPayload, error) {

	//Create Auth payload
	buffer := bytes.NewBuffer(nil)
	buffer.Write(info.PrevMessage)
	buffer.Write(info.Nonce)
	prfBuf, err := info.PRF.GetHMAC(info.ID)
	if err != nil {
		return nil, err
	}
	buffer.Write(prfBuf)

	//
	var body []byte
	if info.AuthType == IKEProtocolAuthType_RSA {
		if data, err := info.PrivateKey.Sign(buffer.Bytes()); err != nil {
			return nil, err
		} else {
			body = data
		}
	} else {
		info.PRF.SetKey(info.PSK)
		p2Prfkey, err := info.PRF.GetHMAC([]byte(IKEPROTOCOL_PSK_PAD))
		if err != nil {
			return nil, err
		}

		info.PRF.SetKey(p2Prfkey)
		if data, err := info.PRF.GetHMAC(buffer.Bytes()); err != nil {
			return nil, err
		} else {
			body = data
		}
	}

	//create payload and add static header
	payload := thisPt.packet.CreatePayload(IKEProtocolPayloadType_AUTH)
	staticHeader := IKEProtocolAuthPayloadHeader{}
	staticHeader.AuthenticationType = info.AuthType
	binary.Write(payload, binary.BigEndian, &staticHeader)

	//write body
	payload.Write(body)
	return payload, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePayloadFactory) CreateDelete(info *IKEPayloadDeleteInfo) (IIKEPayload, error) {

	payload := thisPt.packet.CreatePayload(IKEProtocolPayloadType_D)

	//fill static headers
	header := IKEProtocolDeleteHeader{}
	header.ProtocolId = info.ProtocolID
	if info.SPIList != nil {
		header.NumSPI = uint16(len(info.SPIList))
		header.SPISize = uint8(len(info.SPIList[0]))
	}
	binary.Write(payload, binary.BigEndian, &header)

	if info.SPIList != nil {
		for i := range info.SPIList {
			payload.Write(info.SPIList[i])
		}
	}
	return payload, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePayloadFactory) CreateInitiatorID(id *IKEPayloadIDInfo) (IIKEPayload, error) {
	return thisPt.createIdPayload(IKEProtocolPayloadType_IDi, id)
}

//---------------------------------------------------------------------------------------
func (thisPt *ikePayloadFactory) CreateResponderID(id *IKEPayloadIDInfo) (IIKEPayload, error) {
	return thisPt.createIdPayload(IKEProtocolPayloadType_IDr, id)
}

//---------------------------------------------------------------------------------------
func createPayloadFactory(packet IIKEPacket) IIKEPacketPayloadFactory {
	return &ikePayloadFactory{
		packet: packet,
	}
}

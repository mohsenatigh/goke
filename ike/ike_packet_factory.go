package ike

type ikePacketFactory struct {
}

//---------------------------------------------------------------------------------------
func (thisPT *ikePacketFactory) MakeInit(info *IKEPacketInitInfo) (IIKEPacket, error) {
	packet, _ := createIKEPacket(nil, IKEProtocolExChangeType_IKE_SA_INIT)
	packet.GetPayloadFactory().CreatePhase1Proposal(info.Phase1Proposal)
	packet.GetPayloadFactory().CreateDH(info.DhInfo)
	packet.GetPayloadFactory().CreateNonce(info.Nonce)
	packet.GetPayloadFactory().CreateVendorInfo(info.VendorInfo)

	if info.EnableNat {
		packet.GetPayloadFactory().CreateNAT(&info.NatInfoI)
		packet.GetPayloadFactory().CreateNAT(&info.NatInfoR)
	}

	if info.EnableFragment {
		packet.GetPayloadFactory().CreateFragmentSupport()
	}

	if info.NeedCertRequest {
		packet.GetPayloadFactory().CreateCertRequest(info.Cert, info.Ca)
	}

	if info.Transport {
		packet.GetPayloadFactory().CreateTransportSupport()
	}

	return packet, nil
}

//---------------------------------------------------------------------------------------
func (thisPT *ikePacketFactory) MakeInformationNotify(code uint16) (IIKEPacket, error) {
	packet, _ := createIKEPacket(nil, IKEProtocolExChangeType_INFORMATIONAL)
	packet.GetPayloadFactory().CreateNotify(0, code, nil)
	return packet, nil
}

//---------------------------------------------------------------------------------------
func (thisPT *ikePacketFactory) MakeChildSA(info *IKEPacketChildSAInfo) (IIKEPacket, error) {
	packet, _ := createIKEPacket(nil, IKEProtocolExChangeType_CREATE_CHILD_SA)
	packet.GetPayloadFactory().CreatePhase2Proposal(info.Phase2Proposal)
	packet.GetPayloadFactory().CreateNonce(info.Nonce)
	packet.GetPayloadFactory().CreateTrafficSelector(&info.TSI)
	packet.GetPayloadFactory().CreateTrafficSelector(&info.TSR)
	return packet, nil
}

//---------------------------------------------------------------------------------------
func (thisPT *ikePacketFactory) MakeAuth(info *IKEPacketAuthInfo) (IIKEPacket, error) {
	packet, _ := createIKEPacket(nil, IKEProtocolExChangeType_IKE_AUTH)

	if info.Initiator {
		packet.GetPayloadFactory().CreateInitiatorID(&info.ID)
	} else {
		packet.GetPayloadFactory().CreateResponderID(&info.ID)
	}

	if info.NeedCertRequest {
		packet.GetPayloadFactory().CreateCertRequest(info.Cert, info.Ca)
	}

	if info.NeedCert {
		packet.GetPayloadFactory().CreateCert(info.Cert)
	}

	if info.NeedCFG {
		packet.GetPayloadFactory().CreateConfigurationReply(&info.ConfigurationV4, &info.ConfigurationV6)
	}

	packet.GetPayloadFactory().CreateAuth(&info.Auth)
	packet.GetPayloadFactory().CreatePhase2Proposal(info.Phase2Proposal)
	packet.GetPayloadFactory().CreateTrafficSelector(&info.TSI)
	packet.GetPayloadFactory().CreateTrafficSelector(&info.TSR)
	if info.Transport {
		packet.GetPayloadFactory().CreateTransportSupport()
	}
	packet.GetPayloadFactory().CreateNotify(0, 0, nil)
	return packet, nil
}

//---------------------------------------------------------------------------------------
func (thisPT *ikePacketFactory) MakeDeletePacket(info *IKEPacketDeleteInfo) (IIKEPacket, error) {
	packet, _ := createIKEPacket(nil, IKEProtocolExChangeType_INFORMATIONAL)
	packet.GetPayloadFactory().CreateDelete(&info.DelInfo)
	return packet, nil
}

//---------------------------------------------------------------------------------------
func createIKEPacketFactory() IIKEPacketFactory {
	return &ikePacketFactory{}
}

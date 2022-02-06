package ike

type ikePacketFactory struct {
}

//---------------------------------------------------------------------------------------
func (thisPT *ikePacketFactory) setGeneralInfo(packet IIKEPacket, gInfo *IKEPacketGeneralInfo) {
	//
	if gInfo.Initiator {
		packet.GetHeader().Flags |= IKEProtocolHeaderFlag_Initiator
	} else {
		packet.GetHeader().Flags |= IKEProtocolHeaderFlag_Response
	}

	copy(packet.GetHeader().ISPI[:], gInfo.ISPI)
	copy(packet.GetHeader().RSPI[:], gInfo.RSPI)
}

//---------------------------------------------------------------------------------------
func (thisPT *ikePacketFactory) MakeInit(info *IKEPacketInitInfo) (IIKEPacket, error) {
	packet, _ := createIKEPacket(nil, IKEProtocolExChangeType_IKE_SA_INIT, 0, 0)
	packet.GetPayloadFactory().CreatePhase1Proposal(info.Phase1Proposal)
	packet.GetPayloadFactory().CreateDH(info.DhInfo)
	packet.GetPayloadFactory().CreateNonce(info.Nonce)
	packet.GetPayloadFactory().CreateVendorInfo(info.VendorInfo)

	if info.EnableNat {
		packet.GetPayloadFactory().CreateNAT(&info.NatInfoI, true)
		packet.GetPayloadFactory().CreateNAT(&info.NatInfoR, false)
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

	thisPT.setGeneralInfo(packet, &info.General)
	return packet, nil
}

//---------------------------------------------------------------------------------------
func (thisPT *ikePacketFactory) MakeInformationNotify(code uint16, gInfo *IKEPacketGeneralInfo) (IIKEPacket, error) {
	packet, _ := createIKEPacket(nil, IKEProtocolExChangeType_INFORMATIONAL, gInfo.ESN, gInfo.ESNSize)
	packet.GetPayloadFactory().CreateNotify(0, code, nil)
	thisPT.setGeneralInfo(packet, gInfo)
	return packet, nil
}

//---------------------------------------------------------------------------------------
func (thisPT *ikePacketFactory) MakeChildSA(info *IKEPacketChildSAInfo) (IIKEPacket, error) {
	packet, _ := createIKEPacket(nil, IKEProtocolExChangeType_CREATE_CHILD_SA, info.General.ESN, info.General.ESNSize)
	packet.GetPayloadFactory().CreatePhase2Proposal(info.Phase2Proposal)
	packet.GetPayloadFactory().CreateNonce(info.Nonce)
	packet.GetPayloadFactory().CreateTrafficSelector(&info.TSI)
	packet.GetPayloadFactory().CreateTrafficSelector(&info.TSR)
	thisPT.setGeneralInfo(packet, &info.General)
	return packet, nil
}

//---------------------------------------------------------------------------------------
func (thisPT *ikePacketFactory) MakeAuth(info *IKEPacketAuthInfo) (IIKEPacket, error) {
	packet, _ := createIKEPacket(nil, IKEProtocolExChangeType_IKE_AUTH, info.General.ESN, info.General.ESNSize)

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
	thisPT.setGeneralInfo(packet, &info.General)
	return packet, nil
}

//---------------------------------------------------------------------------------------
func (thisPT *ikePacketFactory) MakeDeletePacket(info *IKEPacketDeleteInfo) (IIKEPacket, error) {
	packet, _ := createIKEPacket(nil, IKEProtocolExChangeType_INFORMATIONAL, info.General.ESN, info.General.ESNSize)
	packet.GetPayloadFactory().CreateDelete(&info.DelInfo)
	thisPT.setGeneralInfo(packet, &info.General)
	return packet, nil
}

//---------------------------------------------------------------------------------------
func createIKEPacketFactory() IIKEPacketFactory {
	return &ikePacketFactory{}
}

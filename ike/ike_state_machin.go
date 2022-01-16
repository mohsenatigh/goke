package ike

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/mohsenatigh/goke/gcrypto"
)

//---------------------------------------------------------------------------------------
type IKEStateMachine struct {
	packetFactory IIKEPacketFactory
	crypto        gcrypto.IGCrypto
	actor         IIKEActor
}

//---------------------------------------------------------------------------------------
func (thisPt *IKEStateMachine) serializeID(id *IKEPayloadIDInfo) []byte {
	buffer := bytes.NewBuffer(nil)
	header := IKEProtocolIDHeader{}
	header.IDType = id.IDType
	binary.Write(buffer, binary.LittleEndian, &header)
	buffer.Write(id.IDData)
	return buffer.Bytes()
}

//---------------------------------------------------------------------------------------
func (thisPt *IKEStateMachine) selectOrReadPhase2Info(packet IIKEPacket, context IIKEProcessContext) (*IKEPayloadProposalInfo, error) {

	var phase2Proposal *IKEPayloadProposalInfo
	otherProposal, err := packet.GetPayloadDissector().GetPhase2Proposal()
	if err != nil {
		return nil, errors.New("no phase2 proposal chosen")
	}

	//check for phase2 match and generate keys
	if prop, have := context.GetPhase2Proposal(); have {
		phase2Proposal = thisPt.haveProposal(&prop, otherProposal, false)
	} else {
		phase2Proposal = thisPt.getBestProposal(otherProposal, false)
	}

	if phase2Proposal == nil {
		return nil, errors.New("no phase2 proposal chosen")
	}
	return phase2Proposal, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *IKEStateMachine) getPhase1DefaultProposal() IKEPayloadProposalInfo {
	proposal := IKEPayloadProposalInfo{}
	proposal.DH = 30
	proposal.EncryptionAlg = IKEProtocolTransformEncALG_ENCR_AES_CBC
	proposal.EncryptionAlgKeyLen = 128
	proposal.IntegrityAlg = IKEProtocolTransformEncALG_HMAC_SHA1
	proposal.Prf = IKEProtocolTransformEncALG_HMAC_SHA1
	proposal.EspSize = 4
	return proposal
}

//---------------------------------------------------------------------------------------
func (thisPt *IKEStateMachine) getPhase2DefaultProposal() IKEPayloadProposalInfo {
	proposal := IKEPayloadProposalInfo{}
	proposal.EncryptionAlg = IKEProtocolTransformEncALG_ENCR_AES_CBC
	proposal.EncryptionAlgKeyLen = 128
	proposal.IntegrityAlg = IKEProtocolTransformEncALG_HMAC_SHA1
	proposal.EspSize = 4
	return proposal
}

//---------------------------------------------------------------------------------------
func (thisPt *IKEStateMachine) isSupportedLocalDH(dh int) error {
	dhMap := map[int]bool{
		19: true,
		20: true,
		21: true,
		27: true,
		28: true,
		29: true,
	}

	if _, fnd := dhMap[dh]; fnd {
		return nil
	}

	return errors.New("unsupported DH group")
}

//---------------------------------------------------------------------------------------
func (thisPt *IKEStateMachine) getLocalEncAlg(ikeenc int, keyLen int) (int, error) {
	type ikeEncInfo [2]int

	algMap := map[ikeEncInfo]int{
		{IKEProtocolTransformEncALG_ENCR_AES_CBC, 128}: gcrypto.GCRYPTO_CIPHER_AES128,
		{IKEProtocolTransformEncALG_ENCR_AES_CBC, 192}: gcrypto.GCRYPTO_CIPHER_AES192,
		{IKEProtocolTransformEncALG_ENCR_AES_CBC, 256}: gcrypto.GCRYPTO_CIPHER_AES256,
	}

	if res, fnd := algMap[ikeEncInfo{ikeenc, keyLen}]; fnd {
		return res, nil
	}

	return -1, errors.New("unsupported encryption protocol")
}

//---------------------------------------------------------------------------------------
func (thisPt *IKEStateMachine) getLocalHMACAlg(ikeHash int) (int, error) {
	algMap := map[int]int{
		IKEProtocolTransformEncALG_HMAC_MD5:    gcrypto.GCRYPTO_HMAC_TYPE_MD5,
		IKEProtocolTransformEncALG_HMAC_SHA1:   gcrypto.GCRYPTO_HMAC_TYPE_SHA1,
		IKEProtocolTransformEncALG_HMAC_SHA256: gcrypto.GCRYPTO_HMAC_TYPE_SHA256,
	}

	if res, fnd := algMap[ikeHash]; fnd {
		return res, nil
	}

	return -1, errors.New("unsupported hmac protocol")
}

//---------------------------------------------------------------------------------------
func (thisPt *IKEStateMachine) getLocalAuthFunc(ikeHash int) (alg int, len int, err error) {
	type ikeAuthInfo [2]int
	algMap := map[int]ikeAuthInfo{
		IKEProtocolAuthFunction_MD5_96:       {gcrypto.GCRYPTO_HMAC_TYPE_MD5, 96},
		IKEProtocolAuthFunction_SHA1_96:      {gcrypto.GCRYPTO_HMAC_TYPE_SHA1, 96},
		IKEProtocolAuthFunction_SHA2_256_128: {gcrypto.GCRYPTO_HMAC_TYPE_SHA256, 128},
	}

	if res, fnd := algMap[ikeHash]; fnd {
		return res[0], res[1], nil
	}

	return -1, -1, errors.New("unsupported hash function")
}

//---------------------------------------------------------------------------------------
func (thisPt *IKEStateMachine) getBestProposal(list []IKEPayloadProposalInfo, phase1 bool) *IKEPayloadProposalInfo {
	for _, l := range list {

		if _, err := thisPt.getLocalEncAlg(l.EncryptionAlg, l.EncryptionAlgKeyLen); err != nil {
			continue
		}

		if _, _, err := thisPt.getLocalAuthFunc(l.IntegrityAlg); err != nil {
			continue
		}

		if phase1 {
			if err := thisPt.isSupportedLocalDH(l.DH); err != nil {
				continue
			}

			if _, err := thisPt.getLocalHMACAlg(l.Prf); err != nil {
				continue
			}
		}
		return &l
	}
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *IKEStateMachine) haveProposal(pIn *IKEPayloadProposalInfo, list []IKEPayloadProposalInfo, phase1 bool) *IKEPayloadProposalInfo {
	for _, item := range list {
		if item.EncryptionAlg != pIn.EncryptionAlg || item.EncryptionAlgKeyLen != pIn.EncryptionAlgKeyLen {
			continue
		}

		if item.IntegrityAlg != pIn.IntegrityAlg {
			continue
		}

		if phase1 {
			if item.DH != pIn.DH {
				continue
			}

			if item.Prf != pIn.Prf {
				continue
			}

		} else {
			if item.ESN != pIn.ESN {
				continue
			}
		}
		return &item
	}
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *IKEStateMachine) calculatePhase2KeyMaterial(session IIKESession) {

	readKey := func(r *bytes.Reader, len int) []byte {
		out := make([]byte, len)
		r.Read(out)
		return out
	}

	bodyBuffer := bytes.NewBuffer(nil)
	bodyBuffer.Write(session.GetInitiatorNonce())
	bodyBuffer.Write(session.GetResponderNonce())

	//
	hmacObj := session.GetPhase1KeyInfo().Prf
	hmacObj.SetKey(session.GetPhase1KeyInfo().SKD)

	//
	prfBuf := thisPt.crypto.CalculatePRFPlus(bodyBuffer.Bytes(), hmacObj)

	//read keys
	prfReader := bytes.NewReader(prfBuf)
	session.GetPhase2KeyInfo().IKey.SKE = readKey(prfReader, session.GetPhase2KeyInfo().Enc.GetKeyLen())
	session.GetPhase2KeyInfo().IKey.SKA = readKey(prfReader, session.GetPhase2KeyInfo().Int.GetLen())
	session.GetPhase2KeyInfo().RKey.SKE = readKey(prfReader, session.GetPhase2KeyInfo().Enc.GetKeyLen())
	session.GetPhase2KeyInfo().RKey.SKA = readKey(prfReader, session.GetPhase2KeyInfo().Int.GetLen())
}

//---------------------------------------------------------------------------------------
func (thisPt *IKEStateMachine) calculatePhase1KeyMaterial(session IIKESession, peerPubKey []byte) error {
	readKey := func(r *bytes.Reader, len int) []byte {
		out := make([]byte, len)
		r.Read(out)
		return out
	}

	//compute symmetric key
	key, err := session.GetDHInfo().ComputeKey(peerPubKey)
	if err != nil {
		return err
	}

	//set PRF key
	hmacObj := session.GetPhase1KeyInfo().Prf
	hmacObj.SetKey(key)

	//{SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr } = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr )
	bodyBuffer := bytes.NewBuffer(nil)
	bodyBuffer.Write(session.GetInitiatorNonce())
	bodyBuffer.Write(session.GetResponderNonce())
	seed, _ := hmacObj.GetHMAC(bodyBuffer.Bytes())

	bodyBuffer.Write(session.GetInitiatorSPI())
	bodyBuffer.Write(session.GetResponderSPI())

	//update key
	hmacObj.SetKey(seed)
	prfBuf := thisPt.crypto.CalculatePRFPlus(bodyBuffer.Bytes(), hmacObj)

	//read keys
	prfReader := bytes.NewReader(prfBuf)
	session.GetPhase1KeyInfo().SKD = readKey(prfReader, session.GetPhase1KeyInfo().Prf.GetLen())
	session.GetPhase1KeyInfo().IKey.SKA = readKey(prfReader, session.GetPhase1KeyInfo().Int.GetLen())
	session.GetPhase1KeyInfo().RKey.SKA = readKey(prfReader, session.GetPhase1KeyInfo().Int.GetLen())
	session.GetPhase1KeyInfo().IKey.SKE = readKey(prfReader, session.GetPhase1KeyInfo().Enc.GetKeyLen())
	session.GetPhase1KeyInfo().RKey.SKE = readKey(prfReader, session.GetPhase1KeyInfo().Enc.GetKeyLen())
	session.GetPhase1KeyInfo().IKey.SKP = readKey(prfReader, session.GetPhase1KeyInfo().Prf.GetLen())
	session.GetPhase1KeyInfo().RKey.SKP = readKey(prfReader, session.GetPhase1KeyInfo().Prf.GetLen())

	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *IKEStateMachine) initSession() {
	//SET DH
	//SET NONCE
}

//---------------------------------------------------------------------------------------
func (thisPt *IKEStateMachine) initSessionIKEKeyObjects(session IIKESession, proposal *IKEPayloadProposalInfo) error {

	//read encryption
	if encAlg, err := thisPt.getLocalEncAlg(proposal.EncryptionAlg, proposal.EncryptionAlgKeyLen); err != nil {
		return err
	} else {
		session.GetPhase1KeyInfo().Enc = thisPt.crypto.GetCipher(encAlg, nil)
	}

	//read integration
	if intAlg, err := thisPt.getLocalHMACAlg(proposal.IntegrityAlg); err != nil {
		return err
	} else {
		session.GetPhase1KeyInfo().Int = thisPt.crypto.GetHMAC(intAlg, nil)
	}

	//read prf
	if intAlg, err := thisPt.getLocalHMACAlg(proposal.Prf); err != nil {
		return err
	} else {
		session.GetPhase1KeyInfo().Prf = thisPt.crypto.GetHMAC(intAlg, nil)
	}

	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *IKEStateMachine) initSessionESPKeyObjects(session IIKESession, proposal *IKEPayloadProposalInfo) error {

	//read encryption
	if encAlg, err := thisPt.getLocalEncAlg(proposal.EncryptionAlg, proposal.EncryptionAlgKeyLen); err != nil {
		return err
	} else {
		session.GetPhase2KeyInfo().Enc = thisPt.crypto.GetCipher(encAlg, nil)
	}

	//read integration
	if intAlg, err := thisPt.getLocalHMACAlg(proposal.IntegrityAlg); err != nil {
		return err
	} else {
		session.GetPhase2KeyInfo().Int = thisPt.crypto.GetHMAC(intAlg, nil)
	}

	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *IKEStateMachine) needCertificate(packet IIKEPacket, context IIKEProcessContext) bool {

	caObject := context.GetProfile().CA
	if caObject == nil {
		return false
	}

	hashList, err := packet.GetPayloadDissector().GetCertRequest()
	if err != nil {
		return false
	}

	infoId := caObject.GetCertSubjectInfoKeyID()
	for _, h := range hashList {
		if bytes.Equal(h, infoId) {
			return true
		}
	}
	return false
}

//---------------------------------------------------------------------------------------
func (thisPt *IKEStateMachine) checkAuth(packet IIKEPacket, context IIKEProcessContext) error {
	//
	session := context.GetSession()

	//read peer ID
	info := IKEPayloadAuthInfo{}
	id := IKEPayloadIDInfo{}

	var err error
	if session.IsInitiator() {
		id, err = packet.GetPayloadDissector().GetResponderID()
	} else {
		id, err = packet.GetPayloadDissector().GetInitiatorID()
	}
	if err != nil {
		return err
	}

	info.ID = thisPt.serializeID(&id)
	info.Initiator = session.IsInitiator()
	info.Nonce = session.GetPeerNonce()
	info.PRF = session.GetPhase1KeyInfo().Prf
	info.PSK = []byte(context.GetProfile().PSK)
	info.PrivateKey = context.GetProfile().PrivateKey
	info.PublicKey = context.GetProfile().Certificate
	info.PrevMessage = session.GetPrevPacket()

	return packet.GetPayloadDissector().ValidateAuth(&info)
}

//---------------------------------------------------------------------------------------
func (thisPt *IKEStateMachine) makeChildSA(context IIKEProcessContext, phase2Proposal *IKEPayloadProposalInfo) (IIKEPacket, error) {
	//
	session := context.GetSession()

	//make child SA
	info := IKEPacketChildSAInfo{}
	info.Nonce = session.GetMyNonce()
	info.Phase2Proposal = []IKEPayloadProposalInfo{*phase2Proposal}
	info.TSI = context.GetProfile().LocalTS
	info.TSR = context.GetProfile().RemoteTS
	if !session.IsInitiator() {
		info.TSI, info.TSR = info.TSR, info.TSI
	}
	return thisPt.packetFactory.MakeChildSA(&info)
}

//---------------------------------------------------------------------------------------
func (thisPt *IKEStateMachine) makeAuth(context IIKEProcessContext, phase2Proposal *IKEPayloadProposalInfo) (IIKEPacket, error) {
	session := context.GetSession()

	//create ID object
	id := IKEPayloadIDInfo{}
	if len(context.GetProfile().FQDN) > 0 {
		id.IDType = IKEProtocolIDType_ID_FQDN
		id.IDData = []byte(context.GetProfile().FQDN)
	} else if context.GetProfile().Certificate != nil {
		id.IDType = IKEProtocolIDType_ID_DER_ASN1_DN
		id.IDData = context.GetProfile().Certificate.GetDER()
	} else {
		if len(context.LocalAddress().IP) == 4 {
			id.IDType = IKEProtocolIDType_ID_IPV4_ADDR
		} else {
			id.IDType = IKEProtocolIDType_ID_IPV6_ADDR
		}
		id.IDData = context.LocalAddress().IP
	}

	//
	info := IKEPacketAuthInfo{}
	info.Initiator = session.IsInitiator()
	info.Ca = context.GetProfile().CA
	info.Cert = context.GetProfile().Certificate
	info.ID = id
	info.NeedCert = session.HaveFlag(IKE_SESSION_FLAG_NEED_CERT)
	info.Transport = session.HaveFlag(IKE_SESSION_FLAG_TRANSPORT)
	if !context.GetProfile().UsePSK && context.GetProfile().PeerCertificate == nil {
		info.NeedCertRequest = true
	}

	//fill traffic selectors
	info.TSI = context.GetProfile().LocalTS
	info.TSR = context.GetProfile().RemoteTS
	if !info.Initiator {
		info.TSI, info.TSR = info.TSR, info.TSI
	}

	//fill authentication payload info
	if context.GetProfile().UsePSK {
		info.Auth.AuthType = IKEProtocolAuthType_PSK
	} else {
		info.Auth.AuthType = IKEProtocolAuthType_RSA
	}
	info.Auth.ID = thisPt.serializeID(&id)
	info.Auth.Initiator = info.Initiator
	info.Auth.Nonce = session.GetMyNonce()
	info.Auth.PRF = session.GetPhase1KeyInfo().Prf
	info.Auth.PSK = []byte(context.GetProfile().PSK)
	info.Auth.PrivateKey = context.GetProfile().PrivateKey
	info.Auth.PublicKey = context.GetProfile().Certificate
	info.Auth.PrevMessage = session.GetPrevPacket()

	//fill phase2 info
	if phase2Proposal != nil {
		info.Phase2Proposal = []IKEPayloadProposalInfo{*phase2Proposal}
	}
	return thisPt.packetFactory.MakeAuth(&info)
}

//---------------------------------------------------------------------------------------
func (thisPt *IKEStateMachine) checkTS(context IIKEProcessContext, its *IKEPayloadTrafficSelectorInfo, rts *IKEPayloadTrafficSelectorInfo) bool {
	//
	compareTS := func(a *IKEPayloadTrafficSelectorInfo, b *IKEPayloadTrafficSelectorInfo) bool {
		if len(a.TrafficPolicy) != len(b.TrafficPolicy) {
			return false
		}

		for i := range a.TrafficPolicy {
			if a.TrafficPolicy[i].Protocol != b.TrafficPolicy[i].Protocol {
				return false
			}

			if a.TrafficPolicy[i].Type != b.TrafficPolicy[i].Type {
				return false
			}

			if !a.TrafficPolicy[i].StartAddress.Equal(b.TrafficPolicy[i].StartAddress) {
				return false
			}

			if !a.TrafficPolicy[i].EndAddress.Equal(b.TrafficPolicy[i].EndAddress) {
				return false
			}

			if a.TrafficPolicy[i].StartPort != b.TrafficPolicy[i].StartPort {
				return false
			}

			if a.TrafficPolicy[i].EndPort != b.TrafficPolicy[i].EndPort {
				return false
			}
		}
		return true
	}
	//
	lits := context.GetProfile().LocalTS
	lrts := context.GetProfile().RemoteTS
	if !context.GetSession().IsInitiator() {
		lits, lrts = lrts, lits
	}

	return (compareTS(&lits, its) && compareTS(&lrts, rts))
}

//---------------------------------------------------------------------------------------
func (thisPt *IKEStateMachine) makeInitResponse(context IIKEProcessContext, proposal *IKEPayloadProposalInfo) (IIKEPacket, error) {
	session := context.GetSession()

	ipI := context.LocalAddress().IP
	ipR := context.RemoteAddress().IP
	if !session.IsInitiator() {
		ipI, ipR = ipR, ipI
	}

	info := IKEPacketInitInfo{
		Phase1Proposal:  []IKEPayloadProposalInfo{*proposal},
		DhInfo:          session.GetDHInfo(),
		Nonce:           session.GetResponderNonce(),
		VendorInfo:      []byte(context.GetProfile().VendorID),
		EnableNat:       context.GetProfile().EnableNat,
		EnableFragment:  session.HaveFlag(IKE_SESSION_FLAG_ENABLE_FRAGMENT),
		NeedCertRequest: session.HaveFlag(IKE_SESSION_FLAG_NEED_CERT),
		Transport:       session.HaveFlag(IKE_SESSION_FLAG_TRANSPORT),
		Ca:              context.GetProfile().CA,
		Cert:            context.GetProfile().Certificate,

		NatInfoI: IKEPayloadNatInfo{
			SPI:  session.GetInitiatorSPI(),
			SPR:  session.GetResponderSPI(),
			IPI:  ipI,
			IPR:  ipR,
			Src:  true,
			Hash: thisPt.crypto.GetHash(gcrypto.GCRYPTO_HASH_TYPE_SHA1),
		},

		NatInfoR: IKEPayloadNatInfo{
			SPI:  session.GetInitiatorSPI(),
			SPR:  session.GetResponderSPI(),
			IPI:  ipI,
			IPR:  ipR,
			Src:  false,
			Hash: thisPt.crypto.GetHash(gcrypto.GCRYPTO_HASH_TYPE_SHA1),
		},
	}

	return thisPt.packetFactory.MakeInit(&info)
}

//---------------------------------------------------------------------------------------
func (thisPt *IKEStateMachine) ProcessInitPacket(packet IIKEPacket, context IIKEProcessContext) (IIKEPacket, error) {

	var phase1Proposal *IKEPayloadProposalInfo
	session := context.GetSession()

	returnErr := func(code uint16, err error) (IIKEPacket, error) {
		packet, _ := thisPt.packetFactory.MakeInformationNotify(code)
		return packet, err
	}

	//check for errors
	if err, code := packet.HasError(); err {
		return nil, fmt.Errorf("packet have error %d ", code)
	}

	//read phase1 sa
	otherProposal, err := packet.GetPayloadDissector().GetPhase1Proposal()
	if err != nil {
		return nil, err
	}

	//check for match
	if prop, have := context.GetPhase1Proposal(); have {
		phase1Proposal = thisPt.haveProposal(&prop, otherProposal, true)
	} else {
		phase1Proposal = thisPt.getBestProposal(otherProposal, true)
	}

	if phase1Proposal == nil {
		return returnErr(IKEProtocolNotifyCodes_NO_PROPOSAL_CHOSEN, errors.New("no proposal chosen for IKE phase 1"))
	}

	//read peer public key
	peerPublicKey, group, err := packet.GetPayloadDissector().GetDH()
	if err != nil {
		return returnErr(IKEProtocolNotifyCodes_INVALID_SYNTAX, err)
	}
	if err = thisPt.isSupportedLocalDH(group); err != nil {
		return returnErr(IKEProtocolNotifyCodes_NO_PROPOSAL_CHOSEN, err)
	}

	//read peer nonce
	peerNonce, err := packet.GetPayloadDissector().GetNonce()
	if err != nil {
		return returnErr(IKEProtocolNotifyCodes_INVALID_SYNTAX, err)
	}
	session.SetRemoteNonce(peerNonce)

	//initialize session crypto objects
	if err := thisPt.initSessionIKEKeyObjects(session, phase1Proposal); err != nil {
		return returnErr(IKEProtocolNotifyCodes_INVALID_SYNTAX, err)
	}

	//calculate phase1 keys
	if err := thisPt.calculatePhase1KeyMaterial(session, peerPublicKey); err != nil {
		return returnErr(IKEProtocolNotifyCodes_INVALID_SYNTAX, err)
	}

	//check for fragmentation
	if packet.GetPayloadDissector().GetHaveFragmentSupport() {
		if !context.GetProfile().EnableFragment {
			return returnErr(IKEProtocolNotifyCodes_NO_PROPOSAL_CHOSEN, errors.New("fragmentation is not supported"))
		}
		session.SetFlag(IKE_SESSION_FLAG_ENABLE_FRAGMENT)
	}

	//check for transport mode
	if packet.GetPayloadDissector().GetHaveTransportSupport() {
		if !context.GetProfile().EnableTransport {
			return returnErr(IKEProtocolNotifyCodes_NO_PROPOSAL_CHOSEN, errors.New("transport mode is not activated"))
		}
		session.SetFlag(IKE_SESSION_FLAG_TRANSPORT)
	}

	//check for nat
	if context.GetProfile().EnableNat {
		session.SetFlag(IKE_SESSION_FLAG_ENABLE_NAT)
	}

	//check for certificate transfer
	if thisPt.needCertificate(packet, context) {
		session.SetFlag(IKE_SESSION_FLAG_NEED_CERT)
	}

	//create response
	if !session.IsInitiator() {
		return thisPt.makeInitResponse(context, phase1Proposal)
	}

	//get phase2 proposal
	phase2Proposal, havePhase2 := context.GetPhase2Proposal()
	if !havePhase2 {
		phase2Proposal = thisPt.getPhase2DefaultProposal()
	}

	return thisPt.makeAuth(context, &phase2Proposal)
}

//---------------------------------------------------------------------------------------
func (thisPt *IKEStateMachine) ProcessAuthPacket(packet IIKEPacket, context IIKEProcessContext) (IIKEPacket, error) {

	session := context.GetSession()

	returnErr := func(code uint16, err error) (IIKEPacket, error) {
		packet, _ := thisPt.packetFactory.MakeInformationNotify(code)
		return packet, err
	}

	//check for error
	if hasErr, errCode := packet.HasError(); hasErr {
		return nil, fmt.Errorf("receive error code %d", errCode)
	}

	//check authentication header
	if err := thisPt.checkAuth(packet, context); err != nil {
		return returnErr(IKEProtocolNotifyCodes_AUTHENTICATION_FAILED, errors.New("authentication failed"))
	}

	//read and check TS
	tsi, err := packet.GetPayloadDissector().GetTrafficSelector(true)
	if err != nil {
		return returnErr(IKEProtocolNotifyCodes_INVALID_KE_PAYLOAD, errors.New("can not read initiator traffic selector"))
	}

	tsr, err := packet.GetPayloadDissector().GetTrafficSelector(false)
	if err != nil {
		return returnErr(IKEProtocolNotifyCodes_INVALID_KE_PAYLOAD, errors.New("can not read responder traffic selector"))
	}

	if !thisPt.checkTS(context, &tsi, &tsr) {
		return returnErr(IKEProtocolNotifyCodes_TS_UNACCEPTABLE, errors.New("invalid traffic selector"))
	}

	//check transport mode
	if packet.GetPayloadDissector().GetHaveTransportSupport() != context.GetProfile().EnableTransport {
		return returnErr(IKEProtocolNotifyCodes_NO_PROPOSAL_CHOSEN, errors.New("traffic selector mismatch"))
	}

	//read phase2 propsal
	phase2Proposal, err := thisPt.selectOrReadPhase2Info(packet, context)
	if err != nil {
		return returnErr(IKEProtocolNotifyCodes_INVALID_KE_PAYLOAD, err)
	}

	//check for phase2 match and generate keys
	if err := thisPt.initSessionESPKeyObjects(session, phase2Proposal); err != nil {
		return returnErr(IKEProtocolNotifyCodes_NO_PROPOSAL_CHOSEN, errors.New("no phase2 proposal chosen"))
	}
	thisPt.calculatePhase2KeyMaterial(session)

	//install session
	thisPt.actor.InstallESP(session)

	//
	if session.IsInitiator() {
		return nil, nil
	}

	//check for certificate transfer
	if thisPt.needCertificate(packet, context) {
		session.SetFlag(IKE_SESSION_FLAG_NEED_CERT)
	}

	return thisPt.makeAuth(context, phase2Proposal)
}

//---------------------------------------------------------------------------------------
func (thisPt *IKEStateMachine) ProcessChildSA(packet IIKEPacket, context IIKEProcessContext) (IIKEPacket, error) {
	//
	session := context.GetSession()

	//return
	returnErr := func(code uint16, err error) (IIKEPacket, error) {
		packet, _ := thisPt.packetFactory.MakeInformationNotify(code)
		return packet, err
	}

	//read new nonce
	peerNonce, err := packet.GetPayloadDissector().GetNonce()
	if err != nil {
		return returnErr(IKEProtocolNotifyCodes_INVALID_SYNTAX, err)
	}
	session.SetRemoteNonce(peerNonce)

	//read phase2 proposal
	phase2Proposal, err := thisPt.selectOrReadPhase2Info(packet, context)
	if err != nil {
		return returnErr(IKEProtocolNotifyCodes_INVALID_KE_PAYLOAD, err)
	}

	//check for phase2 match and generate keys
	if err := thisPt.initSessionESPKeyObjects(session, phase2Proposal); err != nil {
		return returnErr(IKEProtocolNotifyCodes_NO_PROPOSAL_CHOSEN, errors.New("no phase2 proposal chosen"))
	}
	thisPt.calculatePhase2KeyMaterial(session)

	//install new esp key
	thisPt.actor.InstallESP(session)
	if session.IsInitiator() {
		return nil, nil
	}

	//create response packet
	return thisPt.makeChildSA(context, phase2Proposal)
}

//---------------------------------------------------------------------------------------
func (thisPt *IKEStateMachine) ProcessInformation(packet IIKEPacket, context IIKEProcessContext) (IIKEPacket, error) {

	//TODO check for KEEP alive
	if err, code := packet.HasError(); err {
		return nil, fmt.Errorf("receive error code %d ", code)
	}

	if context.GetSession().IsInitiator() {
		return nil, nil
	}

	//TODO check for delete request
	/*delInfo, err := packet.GetPayloadDissector().GetDelete()
	if err != nil {
		return nil, nil
	}

	//check for delete type

	if delInfo.ProtocolID == IKEProtocolProposalHeaderID_IKE {
		context.GetSession().Remove()
	} else if delInfo.ProtocolID == IKEProtocolProposalHeaderID_ESP {

	}*/

	return nil, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *IKEStateMachine) Process(packet IIKEPacket, context IIKEProcessContext) (IIKEPacket, error) {

	switch packet.GetHeader().ExType {
	case IKEProtocolExChangeType_IKE_SA_INIT:
		{
			return thisPt.ProcessInitPacket(packet, context)
		}
	case IKEProtocolExChangeType_IKE_AUTH:
		{
			return thisPt.ProcessAuthPacket(packet, context)
		}
	case IKEProtocolExChangeType_CREATE_CHILD_SA:
		{
			return thisPt.ProcessChildSA(packet, context)
		}
	case IKEProtocolExChangeType_INFORMATIONAL:
		{
			return thisPt.ProcessInformation(packet, context)
		}
	}

	return nil, errors.New("invalid IKE packet")
}

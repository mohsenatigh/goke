package ike

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/mohsenatigh/goke/gcrypto"
)

//---------------------------------------------------------------------------------------
type ikeStateMachine struct {
	packetFactory  IIKEPacketFactory
	crypto         gcrypto.IGCrypto
	actor          IIKEActor
	sessionManager IIKESessionManager
	ikeProfile     IKEProfile
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeStateMachine) terminateSession(session IIKESession) {
	session.UpdateState(IKE_SESSION_STATUS_INIT_TERMINATED)
	session.Remove()
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeStateMachine) serializeID(id *IKEPayloadIDInfo) []byte {
	buffer := bytes.NewBuffer(nil)
	header := IKEProtocolIDHeader{}
	header.IDType = id.IDType
	binary.Write(buffer, binary.LittleEndian, &header)
	buffer.Write(id.IDData)
	return buffer.Bytes()
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeStateMachine) selectOrReadPhase2Info(packet IIKEPacket, context IIKEProcessContext) (*IKEPayloadProposalInfo, error) {

	var phase2Proposal *IKEPayloadProposalInfo
	otherProposal, err := packet.GetPayloadDissector().GetPhase2Proposal()
	if err != nil {
		return nil, errors.New("no phase2 proposal chosen")
	}

	//check for phase2 match and generate keys
	if prop := context.GetProfile().Phase1Proposal; prop != nil {
		phase2Proposal = thisPt.haveProposal(prop, otherProposal, false)
	} else {
		phase2Proposal = thisPt.getBestProposal(otherProposal, false)
	}

	if phase2Proposal == nil {
		return nil, errors.New("no phase2 proposal chosen")
	}
	return phase2Proposal, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeStateMachine) getPhase1DefaultProposal() IKEPayloadProposalInfo {
	proposal := IKEPayloadProposalInfo{}
	proposal.DH = 30
	proposal.EncryptionAlg = gcrypto.IANA_ENCR_AES_CBC
	proposal.EncryptionAlgKeyLen = 128
	proposal.IntegrityAlg = gcrypto.IANA_AUTH_HMAC_SHA1_96
	proposal.Prf = gcrypto.IANA_PRF_HMAC_SHA2_256
	proposal.EspSize = 4
	return proposal
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeStateMachine) getPhase2DefaultProposal() IKEPayloadProposalInfo {
	proposal := IKEPayloadProposalInfo{}
	proposal.EncryptionAlg = gcrypto.IANA_ENCR_AES_CBC
	proposal.EncryptionAlgKeyLen = 128
	proposal.IntegrityAlg = gcrypto.IANA_AUTH_HMAC_SHA1_96
	proposal.EspSize = 4
	return proposal
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeStateMachine) getBestProposal(list []IKEPayloadProposalInfo, phase1 bool) *IKEPayloadProposalInfo {
	for _, l := range list {
		enc := gcrypto.GCryptCipherAlg(l.EncryptionAlg)
		auth := gcrypto.GCryptAuthAlg(l.IntegrityAlg)
		prf := gcrypto.GCryptHmacAlg(l.Prf)
		dhGroup := gcrypto.GCryptoDH(l.DH)

		if !enc.Validate(l.EncryptionAlgKeyLen) {
			continue
		}

		if !auth.Validate() {
			continue
		}

		if phase1 {
			if !dhGroup.Validate() {
				continue
			}

			if !prf.Validate() {
				continue
			}
		}
		return &l
	}
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeStateMachine) haveProposal(pIn *IKEPayloadProposalInfo, list []IKEPayloadProposalInfo, phase1 bool) *IKEPayloadProposalInfo {
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
func (thisPt *ikeStateMachine) calculatePhase2KeyMaterial(session IIKESession) {

	readKey := func(r *bytes.Reader, len int) []byte {
		out := make([]byte, len)
		r.Read(out)
		return out
	}

	bodyBuffer := bytes.NewBuffer(nil)
	bodyBuffer.Write(session.GetInitiatorNonce())
	bodyBuffer.Write(session.GetResponderNonce())

	//
	hmacObj := thisPt.crypto.GetHMAC(session.GetPhase1KeyInfo().Prf, session.GetPhase1KeyInfo().SKD)

	//
	prfBuf := thisPt.crypto.CalculatePRFPlus(bodyBuffer.Bytes(), hmacObj)

	//read keys
	prfReader := bytes.NewReader(prfBuf)
	session.GetPhase2KeyInfo().IKey.SKE = readKey(prfReader, session.GetPhase2KeyInfo().KeyLen/8)
	session.GetPhase2KeyInfo().IKey.SKA = readKey(prfReader, session.GetPhase2KeyInfo().Int.Size())
	session.GetPhase2KeyInfo().RKey.SKE = readKey(prfReader, session.GetPhase2KeyInfo().KeyLen/8)
	session.GetPhase2KeyInfo().RKey.SKA = readKey(prfReader, session.GetPhase2KeyInfo().Int.Size())
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeStateMachine) calculatePhase1KeyMaterial(session IIKESession, peerPubKey []byte) error {
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
	hmacObj := thisPt.crypto.GetHMAC(session.GetPhase1KeyInfo().Prf, key)

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
	session.GetPhase1KeyInfo().SKD = readKey(prfReader, session.GetPhase1KeyInfo().Prf.Size())
	session.GetPhase1KeyInfo().IKey.SKA = readKey(prfReader, session.GetPhase1KeyInfo().Int.Size())
	session.GetPhase1KeyInfo().RKey.SKA = readKey(prfReader, session.GetPhase1KeyInfo().Int.Size())
	session.GetPhase1KeyInfo().IKey.SKE = readKey(prfReader, session.GetPhase1KeyInfo().KeyLen/8)
	session.GetPhase1KeyInfo().RKey.SKE = readKey(prfReader, session.GetPhase1KeyInfo().KeyLen/8)
	session.GetPhase1KeyInfo().IKey.SKP = readKey(prfReader, session.GetPhase1KeyInfo().Prf.Size())
	session.GetPhase1KeyInfo().RKey.SKP = readKey(prfReader, session.GetPhase1KeyInfo().Prf.Size())

	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeStateMachine) initSessionIKEKeyObjects(session IIKESession, proposal *IKEPayloadProposalInfo) error {

	if !proposal.EncryptionAlg.Validate(proposal.EncryptionAlgKeyLen) {
		return errors.New("invalid encryption algorithm")
	}

	if !proposal.IntegrityAlg.Validate() {
		return errors.New("invalid integrity algorithm")
	}

	if !proposal.Prf.Validate() {
		return errors.New("invalid prf algorithm")
	}

	if !proposal.DH.Validate() {
		return errors.New("invalid DH group")
	}

	session.GetPhase1KeyInfo().Enc = proposal.EncryptionAlg
	session.GetPhase1KeyInfo().Int = proposal.IntegrityAlg
	session.GetPhase1KeyInfo().Prf = proposal.Prf
	session.GetPhase1KeyInfo().KeyLen = proposal.EncryptionAlgKeyLen
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeStateMachine) initSessionESPKeyObjects(session IIKESession, proposal *IKEPayloadProposalInfo) error {

	if !proposal.EncryptionAlg.Validate(proposal.EncryptionAlgKeyLen) {
		return errors.New("invalid encryption algorithm")
	}

	if !proposal.IntegrityAlg.Validate() {
		return errors.New("invalid integrity algorithm")
	}

	session.GetPhase2KeyInfo().Enc = proposal.EncryptionAlg
	session.GetPhase2KeyInfo().Int = proposal.IntegrityAlg
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeStateMachine) needCertificate(packet IIKEPacket, context IIKEProcessContext) bool {

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
func (thisPt *ikeStateMachine) checkAuth(packet IIKEPacket, context IIKEProcessContext) error {
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
	info.PRF = thisPt.crypto.GetHMAC(session.GetPhase1KeyInfo().Prf, session.GetPhase1KeyInfo().SKD)
	info.PSK = []byte(context.GetProfile().PSK)
	info.PrivateKey = context.GetProfile().PrivateKey
	info.PublicKey = context.GetProfile().Certificate
	info.PrevMessage = session.GetPrevPacket()

	return packet.GetPayloadDissector().ValidateAuth(&info)
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeStateMachine) makeChildSA(context IIKEProcessContext, phase2Proposal *IKEPayloadProposalInfo) (IIKEPacket, error) {
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
func (thisPt *ikeStateMachine) makeAuth(context IIKEProcessContext, phase2Proposal *IKEPayloadProposalInfo) (IIKEPacket, error) {
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
	info.Auth.PRF = thisPt.crypto.GetHMAC(session.GetPhase1KeyInfo().Prf, session.GetPhase1KeyInfo().SKD)
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
func (thisPt *ikeStateMachine) checkTS(context IIKEProcessContext, its *IKEPayloadTrafficSelectorInfo, rts *IKEPayloadTrafficSelectorInfo) bool {
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
func (thisPt *ikeStateMachine) makeInitResponse(context IIKEProcessContext, proposal *IKEPayloadProposalInfo) (IIKEPacket, error) {
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
			Hash: thisPt.crypto.GetHash(gcrypto.IANA_HASH_SHA1),
		},

		NatInfoR: IKEPayloadNatInfo{
			SPI:  session.GetInitiatorSPI(),
			SPR:  session.GetResponderSPI(),
			IPI:  ipI,
			IPR:  ipR,
			Src:  false,
			Hash: thisPt.crypto.GetHash(gcrypto.IANA_HASH_SHA1),
		},
	}

	return thisPt.packetFactory.MakeInit(&info)
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeStateMachine) processInitPacket(packet IIKEPacket, context IIKEProcessContext) (IIKEPacket, error) {

	var phase1Proposal *IKEPayloadProposalInfo
	session := context.GetSession()

	returnErr := func(code uint16, err error) (IIKEPacket, error) {
		thisPt.terminateSession(session)
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
	if prop := context.GetProfile().Phase2Proposal; prop != nil {
		phase1Proposal = thisPt.haveProposal(prop, otherProposal, true)
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

	if !gcrypto.GCryptoDH(group).Validate() {
		return returnErr(IKEProtocolNotifyCodes_NO_PROPOSAL_CHOSEN, err)
	}

	//check for local DH
	if session.GetDHInfo() == nil {
		session.SetDHInfo(thisPt.crypto.GetDH(phase1Proposal.DH))
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
	session.SetEncrypted(true)

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
		session.UpdateState(IKE_SESSION_STATUS_INIT_RECEIVE)
		return thisPt.makeInitResponse(context, phase1Proposal)
	}

	//get phase2 proposal
	phase2Proposal := thisPt.getPhase2DefaultProposal()
	if context.GetProfile().Phase2Proposal != nil {
		phase2Proposal = *context.GetProfile().Phase2Proposal
	}
	session.UpdateState(IKE_SESSION_STATUS_AUTH_SEND)
	return thisPt.makeAuth(context, &phase2Proposal)
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeStateMachine) processAuthPacket(packet IIKEPacket, context IIKEProcessContext) (IIKEPacket, error) {

	session := context.GetSession()

	returnErr := func(code uint16, err error) (IIKEPacket, error) {
		thisPt.terminateSession(session)
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
	thisPt.actor.InstallESP(context)

	//every thing seems good in my side
	session.UpdateState(IKE_SESSION_STATUS_AUTH_DONE)

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
func (thisPt *ikeStateMachine) processChildSA(packet IIKEPacket, context IIKEProcessContext) (IIKEPacket, error) {
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
	thisPt.actor.InstallESP(context)
	if session.IsInitiator() {
		return nil, nil
	}

	//create response packet
	return thisPt.makeChildSA(context, phase2Proposal)
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeStateMachine) processInformation(packet IIKEPacket, context IIKEProcessContext) (IIKEPacket, error) {

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
func (thisPt *ikeStateMachine) createNewResponderSession(packet IIKEPacket, local, remote *net.UDPAddr) (IIKESession, error) {
	if packet.GetHeader().ExType != IKEProtocolExChangeType_IKE_SA_INIT {
		return nil, errors.New("invalid IKE packet")
	}

	//generate responder SPI
	rspi := thisPt.crypto.GenerateRandom(IKE_PROTOCOL_SP_LEN)
	session, err := thisPt.sessionManager.New(false, packet.GetHeader().ISPI[:], rspi)
	if err != nil {
		return nil, err
	}

	//set nonce
	nonce := thisPt.crypto.GenerateRandom(IKE_PROTOCOL_NONCE_LEN)
	session.SetLocalNonce(nonce)

	return session, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeStateMachine) processPacket(packet IIKEPacket, context IIKEProcessContext) (IIKEPacket, error) {

	state := context.GetSession().GetState()

	switch packet.GetHeader().ExType {
	case IKEProtocolExChangeType_IKE_SA_INIT:
		{
			if state == IKE_SESSION_STATUS_INIT_SEND || state == IKE_SESSION_STATUS_NEW {
				return thisPt.processInitPacket(packet, context)
			}
		}
	case IKEProtocolExChangeType_IKE_AUTH:
		{
			if state == IKE_SESSION_STATUS_AUTH_SEND || state == IKE_SESSION_STATUS_INIT_RECEIVE {
				return thisPt.processAuthPacket(packet, context)
			}
		}
	case IKEProtocolExChangeType_CREATE_CHILD_SA:
		{
			if state == IKE_SESSION_STATUS_AUTH_DONE {
				return thisPt.processChildSA(packet, context)
			}
		}
	case IKEProtocolExChangeType_INFORMATIONAL:
		{
			return thisPt.processInformation(packet, context)
		}
	}

	return nil, errors.New("invalid IKE packet")
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeStateMachine) decryptPacket(packet IIKEPacket, session IIKESession) (IIKEPacket, error) {
	if session.IsEncrypted() {
		enc := thisPt.crypto.GetCipher(session.GetPhase1KeyInfo().Enc, session.GetRemotePhase1Key().SKE)
		auth := thisPt.crypto.GetAuth(session.GetPhase1KeyInfo().Int, session.GetRemotePhase1Key().SKA)
		return packet.Decrypt(enc, auth)
	}
	return packet, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeStateMachine) serializePacket(packet IIKEPacket, session IIKESession) ([]byte, error) {

	buffer := bytes.NewBuffer(nil)

	//check encryption status
	if !session.IsEncrypted() || packet.GetHeader().ExType == IKEProtocolExChangeType_IKE_SA_INIT {
		if err := packet.Serialize(buffer); err != nil {
			return nil, err
		}
	}

	//prepare keys
	enc := thisPt.crypto.GetCipher(session.GetPhase1KeyInfo().Enc, session.GetRemotePhase1Key().SKE)
	auth := thisPt.crypto.GetAuth(session.GetPhase1KeyInfo().Int, session.GetRemotePhase1Key().SKA)

	//encrypt
	if err := packet.Encrypt(buffer, enc, auth); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeStateMachine) updateSeq(packet IIKEPacket, session IIKESession) {
	if session.IsInitiator() {
		packet.SetSequence(IKEProtocolHeaderFlag_Initiator, session.GetExpectedSeq())
	} else {
		packet.SetSequence(IKEProtocolHeaderFlag_Response, session.GetExpectedSeq()-1)
	}
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeStateMachine) Process(in []byte, nat bool, local, remote *net.UDPAddr) ([]byte, error) {

	//create packet
	packet, err := createIKEPacket(bytes.NewBuffer(in), 0)
	if err != nil {
		return nil, err
	}

	//find session
	session := thisPt.sessionManager.Find(packet.GetHeader().ISPI[:], packet.GetHeader().RSPI[:])
	if session == nil {
		session, err = thisPt.createNewResponderSession(packet, local, remote)
		if err != nil {
			return nil, err
		}
	}

	//lock this session
	session.Lock()
	defer session.UnLock()

	//check and update sequence
	if session.GetExpectedSeq() != packet.GetHeader().Id {
		return nil, errors.New("out of order packet")
	}
	session.AddExpectedSeq()

	//decrypt packet
	packet, err = thisPt.decryptPacket(packet, session)
	if err != nil {
		return nil, err
	}

	//create context
	context := createIKEContext(local,
		remote,
		nat,
		&thisPt.ikeProfile,
		session)

	//it is possible that we have both error and packet
	var out []byte
	outP, err := thisPt.processPacket(packet, context)

	if outP != nil {
		thisPt.updateSeq(packet, session)
		out, err = thisPt.serializePacket(packet, session)
	}
	return out, err
}

//---------------------------------------------------------------------------------------
func CreateIKE(actor IIKEActor, profile *IKEProfile) IIKE {

	confSessionMan := ikeSessionManagerConfig{
		halfOpenSessionsLifeTime: profile.HalfOpenSessionsLifeTime,
		inactiveSessionsLifeTime: profile.InactiveSessionsLifeTime,
		removedSessionsLifeTime:  profile.RemovedSessionsLifeTime,
	}

	st := &ikeStateMachine{
		actor:          actor,
		ikeProfile:     *profile,
		sessionManager: createIKESessionManager(&confSessionMan),
		packetFactory:  createIKEPacketFactory(),
		crypto:         gcrypto.CreateCryptoObject(),
	}
	return st
}

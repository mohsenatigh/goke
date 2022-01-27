package ike

import (
	"io"
	"net"

	"github.com/mohsenatigh/goke/gcrypto"
)

//---------------------------------------------------------------------------------------
const (
	IKEProtocolProposalHeaderID_IKE = 1
	IKEProtocolProposalHeaderID_AH  = 2
	IKEProtocolProposalHeaderID_ESP = 3
)

//---------------------------------------------------------------------------------------
const (
	IKEProtocolTrafficSelectorIPVersion_V4 = 7
	IKEProtocolTrafficSelectorIPVersion_V6 = 8
)

//---------------------------------------------------------------------------------------
type IKEPayloadProposalInfo struct {
	EncryptionAlg       gcrypto.GCryptCipherAlg
	EncryptionAlgKeyLen int
	IntegrityAlg        gcrypto.GCryptAuthAlg
	Prf                 gcrypto.GCryptHmacAlg
	DH                  gcrypto.GCryptoDH
	ESN                 int
	Protocol            int
	ESP                 [8]byte
	EspSize             int
}

//---------------------------------------------------------------------------------------
type IKEPayloadConfigurationInfo struct {
	HaveIp     bool
	HaveDNS    bool
	HaveMask   bool
	HaveServer bool
	IP         net.IP
	DNS1       net.IP
	DNS2       net.IP
	Mask       net.IP
	Server     net.IP
}

//---------------------------------------------------------------------------------------
type IKEPayloadNatInfo struct {
	SPI  []byte
	SPR  []byte
	IPI  net.IP
	IPR  net.IP
	Src  bool
	Hash gcrypto.IGCryptoHash
}

//---------------------------------------------------------------------------------------
type IKEPayloadTrafficPolicy struct {
	Type         uint8
	Protocol     uint8
	StartPort    uint16
	EndPort      uint16
	StartAddress net.IP
	EndAddress   net.IP
}

//---------------------------------------------------------------------------------------
type IKEPayloadTrafficSelectorInfo struct {
	Initiator     bool
	TrafficPolicy []IKEPayloadTrafficPolicy
}

//---------------------------------------------------------------------------------------
type IKEPayloadAuthInfo struct {
	Initiator   bool
	PRF         gcrypto.IGCryptoHMAC
	PrevMessage []byte
	Nonce       []byte
	ID          []byte
	PrivateKey  gcrypto.IGCryptoRSA
	PublicKey   gcrypto.IGCryptoRSA
	AuthType    uint8
	PSK         []byte
}

//---------------------------------------------------------------------------------------
type IKEPayloadDeleteInfo struct {
	ProtocolID uint8
	SPIList    [][]byte
}

//---------------------------------------------------------------------------------------
type IKEPayloadIDInfo struct {
	IDType uint8
	IDData []byte
}

//---------------------------------------------------------------------------------------
type IIKEPayload interface {
	GetType() int
	GetHeader() *IKEProtocolPayloadHeader
	GetBodyBuffer() []byte
	Read(buffer []byte) (int, error)
	Write([]byte) (n int, err error)
	Serialize(w io.Writer) error
	ReadRemind() int
	Seek(index int)
}

//---------------------------------------------------------------------------------------
type IIKEPacketPayloadFactory interface {
	CreateCertRequest(cert gcrypto.IGCryptoRSA, ca gcrypto.IGCryptoRSA) (IIKEPayload, error)
	CreateCert(cert gcrypto.IGCryptoRSA) (IIKEPayload, error)
	CreateVendorInfo(vendorInfo []byte) (IIKEPayload, error)
	CreatePhase1Proposal(list []IKEPayloadProposalInfo) (IIKEPayload, error)
	CreateNonce(data []byte) (IIKEPayload, error)
	CreateConfigurationReply(v4Config *IKEPayloadConfigurationInfo, v6Config *IKEPayloadConfigurationInfo) (IIKEPayload, error)
	CreateDH(dh gcrypto.IGCryptoDH) (IIKEPayload, error)
	CreateFragmentSupport() (IIKEPayload, error)
	CreateTransportSupport() (IIKEPayload, error)
	CreateNAT(info *IKEPayloadNatInfo) (IIKEPayload, error)
	CreatePhase2Proposal(list []IKEPayloadProposalInfo) (IIKEPayload, error)
	CreateTrafficSelector(info *IKEPayloadTrafficSelectorInfo) (IIKEPayload, error)
	CreateAuth(info *IKEPayloadAuthInfo) (IIKEPayload, error)
	CreateDelete(info *IKEPayloadDeleteInfo) (IIKEPayload, error)
	CreateInitiatorID(id *IKEPayloadIDInfo) (IIKEPayload, error)
	CreateResponderID(id *IKEPayloadIDInfo) (IIKEPayload, error)
	CreateNotify(protocolId uint8, code uint16, data []byte) (IIKEPayload, error)
}

//---------------------------------------------------------------------------------------
type IIKEPacketPayloadDissector interface {
	GetCertRequest() ([][]byte, error)
	GetCert() ([]byte, error)
	GetVendorInfo() ([]byte, error)
	GetNonce() ([]byte, error)
	GetDH() ([]byte, int, error)
	GetHaveFragmentSupport() bool
	GetHaveTransportSupport() bool
	GetNAT(source bool) ([]byte, error)
	GetPhase1Proposal() ([]IKEPayloadProposalInfo, error)
	GetPhase2Proposal() ([]IKEPayloadProposalInfo, error)
	GetTrafficSelector(initiator bool) (IKEPayloadTrafficSelectorInfo, error)
	ValidateAuth(info *IKEPayloadAuthInfo) error
	GetDelete() (IKEPayloadDeleteInfo, error)
	GetInitiatorID() (IKEPayloadIDInfo, error)
	GetResponderID() (IKEPayloadIDInfo, error)
}

//---------------------------------------------------------------------------------------
type IIKEPacket interface {
	GetHeader() *IKEProtocolHeader
	GetPayload(code int, index int) IIKEPayload
	CreatePayload(code int) IIKEPayload
	CreateFreePayload(code int) IIKEPayload
	Serialize(w io.Writer) error
	Encrypt(w io.Writer, encrypt gcrypto.IGCryptoCipher, auth gcrypto.IGCryptoHMAC) error
	Decrypt(encrypt gcrypto.IGCryptoCipher, auth gcrypto.IGCryptoHMAC) (IIKEPacket, error)
	Load(r io.Reader) error
	Dump() string
	GetPayloadDissector() IIKEPacketPayloadDissector
	GetPayloadFactory() IIKEPacketPayloadFactory
	HasError() (bool, int)
	SetSequence(flag uint8, seq uint32)
}

//---------------------------------------------------------------------------------------
type IKEPacketInitInfo struct {
	Phase1Proposal  []IKEPayloadProposalInfo
	DhInfo          gcrypto.IGCryptoDH
	Nonce           []byte
	VendorInfo      []byte
	EnableNat       bool
	NatInfoI        IKEPayloadNatInfo
	NatInfoR        IKEPayloadNatInfo
	EnableFragment  bool
	NeedCertRequest bool
	Cert            gcrypto.IGCryptoRSA
	Ca              gcrypto.IGCryptoRSA
	Transport       bool
}

//---------------------------------------------------------------------------------------
type IKEPacketChildSAInfo struct {
	Nonce          []byte
	Phase2Proposal []IKEPayloadProposalInfo
	TSI            IKEPayloadTrafficSelectorInfo
	TSR            IKEPayloadTrafficSelectorInfo
}

//---------------------------------------------------------------------------------------
type IKEPacketAuthInfo struct {
	Initiator       bool
	ID              IKEPayloadIDInfo
	Cert            gcrypto.IGCryptoRSA
	Ca              gcrypto.IGCryptoRSA
	NeedCertRequest bool
	NeedCert        bool
	Auth            IKEPayloadAuthInfo
	Phase2Proposal  []IKEPayloadProposalInfo
	TSI             IKEPayloadTrafficSelectorInfo
	TSR             IKEPayloadTrafficSelectorInfo
	Transport       bool
	NeedCFG         bool
	ConfigurationV4 IKEPayloadConfigurationInfo
	ConfigurationV6 IKEPayloadConfigurationInfo
}

//---------------------------------------------------------------------------------------
type IKEPacketDeleteInfo struct {
	DelInfo IKEPayloadDeleteInfo
}

//---------------------------------------------------------------------------------------
type IIKEPacketFactory interface {
	MakeInit(info *IKEPacketInitInfo) (IIKEPacket, error)
	MakeInformationNotify(code uint16) (IIKEPacket, error)
	MakeChildSA(info *IKEPacketChildSAInfo) (IIKEPacket, error)
	MakeAuth(info *IKEPacketAuthInfo) (IIKEPacket, error)
	MakeDeletePacket(info *IKEPacketDeleteInfo) (IIKEPacket, error)
}

//---------------------------------------------------------------------------------------
type IKEPhase1Key struct {
	SKA []byte
	SKE []byte
	SKP []byte
}

//---------------------------------------------------------------------------------------
type IKEPhase1KeyInfo struct {
	IKey   IKEPhase1Key
	RKey   IKEPhase1Key
	SKD    []byte
	Prf    gcrypto.GCryptHmacAlg
	Enc    gcrypto.GCryptCipherAlg
	Int    gcrypto.GCryptAuthAlg
	KeyLen int
}

//---------------------------------------------------------------------------------------
type IKEPhase2Key struct {
	SKA []byte
	SKE []byte
}

//---------------------------------------------------------------------------------------
type IKEPhase2KeyInfo struct {
	IKey   IKEPhase2Key
	RKey   IKEPhase2Key
	Enc    gcrypto.GCryptCipherAlg
	Int    gcrypto.GCryptAuthAlg
	KeyLen int
}

//---------------------------------------------------------------------------------------
const (
	IKE_SESSION_STATUS_NEW             = 1
	IKE_SESSION_STATUS_INIT_SEND       = 2
	IKE_SESSION_STATUS_INIT_RECEIVE    = 3
	IKE_SESSION_STATUS_AUTH_SEND       = 4
	IKE_SESSION_STATUS_AUTH_DONE       = 5
	IKE_SESSION_STATUS_INIT_TERMINATED = 6
)

//---------------------------------------------------------------------------------------
const (
	IKE_SESSION_FLAG_ENABLE_NAT      = 0x1
	IKE_SESSION_FLAG_ENABLE_FRAGMENT = 0x2
	IKE_SESSION_FLAG_NEED_CERT       = 0x4
	IKE_SESSION_FLAG_TRANSPORT       = 0x8
)

//---------------------------------------------------------------------------------------
type IIKESession interface {
	IsInitiator() bool
	GetId() uint64
	Remove()
	IsActive() bool
	IsHalfOpen() bool
	IsEncrypted() bool
	SetEncrypted(bool)
	GetCreationTime() int64
	GetAccessTime() int64
	SetLocalNonce([]byte)
	SetRemoteNonce([]byte)
	GetInitiatorNonce() []byte
	GetResponderNonce() []byte
	GetMyNonce() []byte
	GetPeerNonce() []byte
	GetDHInfo() gcrypto.IGCryptoDH
	SetDHInfo(gcrypto.IGCryptoDH)
	GetInitiatorSPI() []byte
	GetResponderSPI() []byte
	GetPhase1KeyInfo() *IKEPhase1KeyInfo
	GetPhase2KeyInfo() *IKEPhase2KeyInfo
	GetLocalPhase1Key() *IKEPhase1Key
	GetRemotePhase1Key() *IKEPhase1Key
	SetFlag(uint64)
	HaveFlag(uint64) bool
	GetPrevPacket() []byte
	SetPrevPacket([]byte)
	Lock()
	UnLock()
	GetState() int
	UpdateState(int)
	GetAddr() (*net.UDPAddr, *net.UDPAddr)
	GetNATAddr() (*net.UDPAddr, *net.UDPAddr)
	SetNATAddr(local *net.UDPAddr, remote *net.UDPAddr)
	GetExpectedSeq() uint32
	AddExpectedSeq()
}

//---------------------------------------------------------------------------------------
type IKEProfile struct {
	HalfOpenSessionsLifeTime int64
	InactiveSessionsLifeTime int64
	RemovedSessionsLifeTime  int64
	EnableTransport          bool
	EnableFragment           bool
	EnableNat                bool
	CA                       gcrypto.IGCryptoRSA
	Certificate              gcrypto.IGCryptoRSA
	PrivateKey               gcrypto.IGCryptoRSA
	PeerCertificate          gcrypto.IGCryptoRSA
	VendorID                 string
	PSK                      string
	UsePSK                   bool
	FQDN                     string
	LocalTS                  IKEPayloadTrafficSelectorInfo
	RemoteTS                 IKEPayloadTrafficSelectorInfo
	Phase1Proposal           *IKEPayloadProposalInfo
	Phase2Proposal           *IKEPayloadProposalInfo
	Cookie                   interface{}
}

//---------------------------------------------------------------------------------------
type IIKEProcessContext interface {
	RemoteAddress() *net.UDPAddr
	LocalAddress() *net.UDPAddr
	Nat() bool
	GetProfile() IKEProfile
	GetSession() IIKESession
}

//---------------------------------------------------------------------------------------
type IIKEStateMachin interface {
	Process(Packet IIKEPacket, context IIKEProcessContext) (IIKEPacket, error)
	Init(context IIKEProcessContext) (IIKEPacket, error)
}

//---------------------------------------------------------------------------------------
type IIKESessionManager interface {
	Find(spi []byte, spr []byte) IIKESession
	New(initiator bool, spi []byte, spr []byte) (IIKESession, error)
	Timer(cTime int64) int
}

//---------------------------------------------------------------------------------------
type IIKEActor interface {
	InstallESP(context IIKEProcessContext)
	RemoveESP(context IIKEProcessContext)
	SendControlData(data []byte, context IIKEProcessContext)
}

//---------------------------------------------------------------------------------------
type IIKE interface {
	Process(in []byte, nat bool, local *net.UDPAddr, remote *net.UDPAddr) ([]byte, error)
}

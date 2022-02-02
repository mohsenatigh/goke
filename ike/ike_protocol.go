package ike

const (
	IKE_PROTOCOL_NONCE_LEN = 32
)

//---------------------------------------------------------------------------------------
const (
	IKEProtocolHeaderFlag_Initiator = 0x08
	IKEProtocolHeaderFlag_Response  = 0x20
)

//---------------------------------------------------------------------------------------
const (
	IKEProtocolExChangeType_IKE_SA_INIT     = 34
	IKEProtocolExChangeType_IKE_AUTH        = 35
	IKEProtocolExChangeType_CREATE_CHILD_SA = 36
	IKEProtocolExChangeType_INFORMATIONAL   = 37
)

//---------------------------------------------------------------------------------------
const (
	IKEProtocolTransformType_ENCR  = 1
	IKEProtocolTransformType_PRF   = 2
	IKEProtocolTransformType_INTEG = 3
	IKEProtocolTransformType_DH    = 4
	IKEProtocolTransformType_ESN   = 5
)

//---------------------------------------------------------------------------------------
const (
	IKEProtocolPayloadType_P          = 2 // proposal
	IKEProtocolPayloadType_T          = 3 // transform
	IKEProtocolPayloadType_SA         = 33
	IKEProtocolPayloadType_KE         = 34
	IKEProtocolPayloadType_IDi        = 35
	IKEProtocolPayloadType_IDr        = 36
	IKEProtocolPayloadType_CERT       = 37
	IKEProtocolPayloadType_CERTREQ    = 38
	IKEProtocolPayloadType_AUTH       = 39
	IKEProtocolPayloadType_NIR        = 40
	IKEProtocolPayloadType_N          = 41
	IKEProtocolPayloadType_D          = 42
	IKEProtocolPayloadType_V          = 43
	IKEProtocolPayloadType_TSI        = 44
	IKEProtocolPayloadType_TSR        = 45
	IKEProtocolPayloadType_E          = 46
	IKEProtocolPayloadType_CP         = 47
	IKEProtocolPayloadType_EAP        = 48
	IKEProtocolPayloadType_Fragmented = 53
)

//---------------------------------------------------------------------------------------
const (
	IKEProtocolConfigurationAttributeType_IPv4       = 1
	IKEProtocolConfigurationAttributeType_NetMask    = 2
	IKEProtocolConfigurationAttributeType_DNS        = 3
	IKEProtocolConfigurationAttributeType_NBNS       = 4
	IKEProtocolConfigurationAttributeType_IPv4DHCP   = 6
	IKEProtocolConfigurationAttributeType_VERSION    = 7
	IKEProtocolConfigurationAttributeType_IPv6       = 8
	IKEProtocolConfigurationAttributeType_IPv6DNS    = 10
	IKEProtocolConfigurationAttributeType_IPv6DHCP   = 12
	IKEProtocolConfigurationAttributeType_IPv4Subnet = 13
	IKEProtocolConfigurationAttributeType_Ipv6Subnet = 15
	IKEProtocolConfigurationAttributeType_IPv4Server = 0x5ba0
	IKEProtocolConfigurationAttributeType_IPv6Server = 0x5ba1
)

//---------------------------------------------------------------------------------------
const (
	IKEProtocolNotifyCodes_UNSUPPORTED_CRITICAL_PAYLOAD  = 1
	IKEProtocolNotifyCodes_INVALID_IKE_SPI               = 4
	IKEProtocolNotifyCodes_INVALID_MAJOR_VERSION         = 5
	IKEProtocolNotifyCodes_INVALID_SYNTAX                = 7
	IKEProtocolNotifyCodes_INVALID_MESSAGE_ID            = 9
	IKEProtocolNotifyCodes_INVALID_SPI                   = 11
	IKEProtocolNotifyCodes_NO_PROPOSAL_CHOSEN            = 14
	IKEProtocolNotifyCodes_INVALID_KE_PAYLOAD            = 17
	IKEProtocolNotifyCodes_AUTHENTICATION_FAILED         = 24
	IKEProtocolNotifyCodes_SINGLE_PAIR_REQUIRED          = 34
	IKEProtocolNotifyCodes_NO_ADDITIONAL_SAS             = 35
	IKEProtocolNotifyCodes_INTERNAL_ADDRESS_FAILURE      = 36
	IKEProtocolNotifyCodes_FAILED_CP_REQUIRED            = 37
	IKEProtocolNotifyCodes_TS_UNACCEPTABLE               = 38
	IKEProtocolNotifyCodes_INVALID_SELECTORS             = 39
	IKEProtocolNotifyCodes_TEMPORARY_FAILURE             = 43
	IKEProtocolNotifyCodes_CHILD_SA_NOT_FOUND            = 44
	IKEProtocolNotifyCodes_INITIAL_CONTACT               = 16384
	IKEProtocolNotifyCodes_SET_WINDOW_SIZE               = 16385
	IKEProtocolNotifyCodes_ADDITIONAL_TS_POSSIBLE        = 16386
	IKEProtocolNotifyCodes_IPCOMP_SUPPORTED              = 16387
	IKEProtocolNotifyCodes_NAT_DETECTION_SOURCE_IP       = 16388
	IKEProtocolNotifyCodes_NAT_DETECTION_DESTINATION_IP  = 16389
	IKEProtocolNotifyCodes_COOKIE                        = 16390
	IKEProtocolNotifyCodes_USE_TRANSPORT_MODE            = 16391
	IKEProtocolNotifyCodes_HTTP_CERT_LOOKUP_SUPPORTED    = 16392
	IKEProtocolNotifyCodes_REKEY_SA                      = 16393
	IKEProtocolNotifyCodes_ESP_TFC_PADDING_NOT_SUPPORTED = 16394
	IKEProtocolNotifyCodes_NON_FIRST_FRAGMENTS_ALSO      = 16395
	IKEProtocolNotifyCodes_FRAGMENT_SUPPORTED            = 16430
)

//---------------------------------------------------------------------------------------
const (
	IKEProtocolAuthType_RSA = 1
	IKEProtocolAuthType_PSK = 2
	IKEProtocolAuthType_DSS = 3
)

//---------------------------------------------------------------------------------------
const (
	IKEProtocolIDType_ID_IPV4_ADDR   = 1
	IKEProtocolIDType_ID_FQDN        = 2
	IKEProtocolIDType_ID_RFC822_ADDR = 3
	IKEProtocolIDType_ID_IPV6_ADDR   = 5
	IKEProtocolIDType_ID_DER_ASN1_DN = 9
	IKEProtocolIDType_ID_DER_ASN1_GN = 10
	IKEProtocolIDType_ID_KEY_ID      = 11
)

//---------------------------------------------------------------------------------------
const IKEPROTOCOL_PSK_PAD = "Key Pad for IKEv2"

//---------------------------------------------------------------------------------------
type IKEProtocolProposalTransformKeyInfo struct {
	Type   uint16
	KeyLen uint16
}

//---------------------------------------------------------------------------------------
type IKEProtocolProposalTransformHeader struct {
	TransformType uint8
	Reserved      uint8
	TransformID   uint16
}

//---------------------------------------------------------------------------------------
type IKEProtocolProposalHeader struct {
	PNumber   uint8
	ID        uint8
	SPISize   uint8
	Transform uint8
}

//---------------------------------------------------------------------------------------
const IKEProtocolHeaderSize = 28
const IKEProtocolPayloadHeaderSize = 4

type IKEProtocolHeader struct {
	ISPI     [8]uint8
	RSPI     [8]uint8
	NPayload uint8
	Version  uint8
	ExType   uint8
	Flags    uint8
	Id       uint32
	Length   uint32
}

//---------------------------------------------------------------------------------------
type IKEProtocolPayloadHeader struct {
	NextPayload uint8
	Reserved    uint8
	PayloadLen  uint16
}

//---------------------------------------------------------------------------------------
type IKEProtocolNotifyStaticHeader struct {
	ProtocolID        uint8
	SpiSize           uint8
	NotifyMessageType uint16
}

//---------------------------------------------------------------------------------------
type IKEProtocolConfigurationAttributeHeader struct {
	AttType uint16
	Length  uint16
}

//---------------------------------------------------------------------------------------
type IKEProtocolDHKeyHeader struct {
	Group uint16
	Res   uint16
}

//---------------------------------------------------------------------------------------
type IKEProtocolTrafficSelectorHeader struct {
	TSCount uint8
	RES     [3]byte
}

//---------------------------------------------------------------------------------------
type IKEProtocolTrafficSelectorItemStaticHeader struct {
	TSType    uint8
	IPProto   uint8
	Len       uint16
	StartPort uint16
	EndPort   uint16
}

//---------------------------------------------------------------------------------------
type IKEProtocolAuthPayloadHeader struct {
	AuthenticationType uint8
	RES                [3]byte
}

//---------------------------------------------------------------------------------------
type IKEProtocolDeleteHeader struct {
	ProtocolId uint8
	SPISize    uint8
	NumSPI     uint16
}

//---------------------------------------------------------------------------------------
type IKEProtocolIDHeader struct {
	IDType uint8
	RES    [3]byte
}

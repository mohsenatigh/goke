package ike

import (
	"bytes"
	"testing"

	"github.com/mohsenatigh/goke/gcrypto"
)

func TestIKEPacketFactoryInitPacket(t *testing.T) {

	iSpi := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8}
	rSpi := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8}
	ipi := []byte{192, 168, 1, 1}
	ipr := []byte{192, 168, 1, 2}

	info := IKEPacketInitInfo{
		Phase1Proposal: []IKEPayloadProposalInfo{
			{
				EncryptionAlg:       gcrypto.IANA_ENCR_AES_CBC,
				EncryptionAlgKeyLen: 16,
				IntegrityAlg:        gcrypto.IANA_AUTH_HMAC_SHA1_96,
				Prf:                 gcrypto.IANA_PRF_HMAC_SHA1,
				DH:                  gcrypto.IANA_DH_GROUP_27,
			},
		},
		DhInfo:     gcrypto.CreateCryptoObject().GetDH(gcrypto.IANA_DH_GROUP_27),
		Nonce:      make([]byte, 64),
		VendorInfo: []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9},
		EnableNat:  true,
		NatInfoI: IKEPayloadNatInfo{
			SPI:  iSpi,
			SPR:  rSpi,
			IPI:  ipi,
			IPR:  ipr,
			Src:  true,
			Hash: gcrypto.CreateCryptoObject().GetHash(gcrypto.IANA_HASH_SHA1),
		},
		NatInfoR: IKEPayloadNatInfo{
			SPI:  rSpi,
			SPR:  iSpi,
			IPI:  ipr,
			IPR:  ipi,
			Src:  true,
			Hash: gcrypto.CreateCryptoObject().GetHash(gcrypto.IANA_HASH_SHA1),
		},
		EnableFragment:  true,
		NeedCertRequest: false,
	}

	factory := createIKEPacketFactory()
	packet, err := factory.MakeInit(&info)
	if err != nil {
		t.FailNow()
	}

	//serialize packate
	data := bytes.NewBuffer(nil)
	if err := packet.Serialize(data); err != nil {
		t.FailNow()
	}

	//test packet
	packet, err = createIKEPacket(data, 0)
	if err != nil {
		t.FailNow()
	}

	//check segments
	if _, dh, err := packet.GetPayloadDissector().GetDH(); err != nil || dh != 27 {
		t.FailNow()
	}

	phase1, err := packet.GetPayloadDissector().GetPhase1Proposal()
	if err != nil || len(phase1) == 0 {
		t.FailNow()
	}

	//phase1
	if phase1[0].Prf != gcrypto.IANA_PRF_HMAC_SHA1 ||
		phase1[0].EncryptionAlg != gcrypto.IANA_ENCR_AES_CBC ||
		phase1[0].EncryptionAlgKeyLen != 16 ||
		phase1[0].IntegrityAlg != gcrypto.IANA_AUTH_HMAC_SHA1_96 {
		t.FailNow()
	}

}

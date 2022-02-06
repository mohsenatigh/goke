package ike

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/mohsenatigh/goke/gcrypto"
)

//---------------------------------------------------------------------------------------
func TestIKEProtocolPacketTestInvalidInput(t *testing.T) {
	initPacket, _ := hex.DecodeString(
		"634d203452fe98640000000000000000212022080000000000000128220000300200002")
	_, err := createIKEPacket(bytes.NewBuffer(initPacket), 0, 0, 0)
	if err == nil {
		t.FailNow()
	}
}

//---------------------------------------------------------------------------------------
func TestProtocolPacketTestEncryptionProcess(t *testing.T) {

	//test packet creation
	packet, err := createIKEPacket(nil, IKEProtocolExChangeType_IKE_AUTH, 0, 0)
	if err != nil {
		t.FailNow()
	}

	//create nonce
	cr := gcrypto.CreateCryptoObject()
	authAlg := gcrypto.IANA_AUTH_HMAC_SHA1_96
	encAlg := gcrypto.IANA_ENCR_AES_CBC
	keySize := 16

	authKey := cr.GenerateRandom(authAlg.KeySize())
	encKey := cr.GenerateRandom(keySize)
	nonce := cr.GenerateRandom(64)

	if _, err := packet.GetPayloadFactory().CreateNonce(nonce); err != nil {
		t.FailNow()
	}

	//encrypt packet
	out := bytes.NewBuffer(nil)
	auth := cr.GetAuth(authAlg, authKey)
	enc := cr.GetCipher(encAlg, encKey)
	if packet.Encrypt(out, cr, enc, auth) != nil {
		t.FailNow()
	}

	//decrypt packet
	dPacket, err := createIKEPacket(out, 0, 0, 0)
	if err != nil {
		t.FailNow()
	}

	dPacket, err = dPacket.Decrypt(enc, auth)
	if err != nil {
		t.FailNow()
	}

	//check nonce
	nNonce, err := dPacket.GetPayloadDissector().GetNonce()
	if err != nil {
		t.FailNow()
	}

	if !bytes.Equal(nNonce, nonce) {
		t.FailNow()
	}
}

//---------------------------------------------------------------------------------------
func TestIKEProtocolPacketTestInitProcess(t *testing.T) {
	initPacket, _ := hex.DecodeString(
		"634d203452fe98640000000000000000212022080000000000000128220000300200002c010100040300000c01f9000c800e00800300000803f9000c0300000802f900050300000804f9001b28000040001b000047b3dac4b5ec1fa6d0adb6266209c2b22c3043991e131b4e7e058b82015768adec580609df84d89966a56acd398aff596488ae36bb53d81d2b00004486403d15ceac7cefb5ea23e4e94d78ce9a799b2b64ef574da110ebb65c96ba8951cb78293f6336eb63214a213617dc706f7c1f3eef64100b16ccdfe5347aee872900001810182232641018223265101820336610131934672900001c010040054f183878783d52084cdbcbb6486aa17afbf71e572900001c010040044f183878783d52084cdbcbb6486aa17afbf71e57000000080000402e")

	//test packet creation
	packet, err := createIKEPacket(bytes.NewBuffer(initPacket), 0, 0, 0)
	if err != nil {
		t.FailNow()
	}

	//check header
	if int(packet.GetHeader().Length) != len(initPacket) {
		t.FailNow()
	}

	//check proposal
	proposal, err := packet.GetPayloadDissector().GetPhase1Proposal()
	if err != nil || len(proposal) == 0 {
		t.FailNow()
	}

	if proposal[0].EncryptionAlg != gcrypto.IANA_ENCR_AES_CBC || proposal[0].EncryptionAlgKeyLen != 16 {
		t.FailNow()
	}

	if proposal[0].IntegrityAlg != gcrypto.IANA_AUTH_HMAC_SHA2_256_128 {
		t.FailNow()
	}

	if proposal[0].Prf != gcrypto.IANA_PRF_HMAC_SHA2_256 {
		t.FailNow()
	}

	if proposal[0].DH != gcrypto.IANA_DH_GROUP_27 {
		t.FailNow()
	}

	//check public key
	_, group, err := packet.GetPayloadDissector().GetDH()
	if err != nil || group != 27 {
		t.FailNow()
	}

	//check nonce
	if nonce, err := packet.GetPayloadDissector().GetNonce(); err != nil || len(nonce) != 64 {
		t.FailNow()
	}

	//check vendor id
	if vendorId, err := packet.GetPayloadDissector().GetVendorInfo(); err != nil || len(vendorId) != 20 {
		t.FailNow()
	}

	//
	if !packet.GetPayloadDissector().GetHaveFragmentSupport() {
		t.FailNow()
	}

	if _, err := packet.GetPayloadDissector().GetNAT(true); err != nil {
		t.FailNow()
	}

	if _, err := packet.GetPayloadDissector().GetNAT(false); err != nil {
		t.FailNow()
	}

}

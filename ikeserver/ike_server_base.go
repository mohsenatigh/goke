package ikeserver

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/mohsenatigh/goke/gcrypto"
	"github.com/mohsenatigh/goke/ike"
)

//
type ikeServerBase struct {
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeServerBase) getProposalInfo(str string) (*ike.IKEPayloadProposalInfo, error) {
	info, err := gcrypto.ParseAlgorithm(str)
	if err != nil {
		return nil, err
	}
	ikeInfo := &ike.IKEPayloadProposalInfo{}
	ikeInfo.DH = info.DhGroup
	ikeInfo.EncryptionAlg = info.EncAlg
	ikeInfo.EncryptionAlgKeyLen = info.EncKeyLen
	ikeInfo.IntegrityAlg = info.IntAlg
	ikeInfo.Prf = info.Prf
	return ikeInfo, err
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeServerBase) createTrafficSelector(network string) (ike.IKEPayloadTrafficSelectorInfo, error) {
	ts := ike.IKEPayloadTrafficSelectorInfo{}
	tp := ike.IKEPayloadTrafficPolicy{
		Type:    ike.IKEProtocolTrafficSelectorIPVersion_V4,
		EndPort: 0xffff,
	}
	var err error
	//parse IP
	parseAddress := func(in string) (net.IP, net.IP, error) {
		addList := strings.Split(in, "-")
		if len(addList) != 2 {
			return nil, nil, fmt.Errorf("invalid address range %s", in)
		}
		sIp := net.ParseIP(addList[0])
		eIp := net.ParseIP(addList[1])
		if sIp == nil || eIp == nil {
			return nil, nil, fmt.Errorf("invalid address range %s", in)
		}
		if sIp.To4() != nil {
			sIp = sIp.To4()
		}
		if eIp.To4() != nil {
			eIp = eIp.To4()
		}
		if len(sIp) != len(eIp) {
			return nil, nil, fmt.Errorf("invalid address range %s", in)
		}
		return sIp, eIp, nil
	}

	tp.StartAddress, tp.EndAddress, err = parseAddress(network)
	if err != nil {
		return ts, err
	}
	ts.TrafficPolicy = append(ts.TrafficPolicy, tp)
	return ts, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeServerBase) createIKEInstance(config *IKEServerIKEConfig) (ike.IIKE, error) {

	//
	var ca gcrypto.IGCryptoRSA
	var cert gcrypto.IGCryptoRSA
	var pkey gcrypto.IGCryptoRSA
	var peerCert gcrypto.IGCryptoRSA

	//read CA
	if len(config.CaFile) > 0 {
		ca = gcrypto.CreateCryptoObject().GetRSA(config.CaFile, "")
		if ca == nil {
			return nil, errors.New("invalid CA")
		}
	}

	//read certificate
	if len(config.CertificateFile) > 0 {
		cert = gcrypto.CreateCryptoObject().GetRSA(config.CertificateFile, "")
		if cert == nil {
			return nil, errors.New("invalid certificate file")
		}
	}

	//read private key
	if len(config.PrivateKeyFile) > 0 {
		pkey = gcrypto.CreateCryptoObject().GetRSA("", config.PrivateKeyFile)
		if pkey == nil {
			return nil, errors.New("invalid private key file")
		}
	}

	//read peer cert
	if len(config.PeerCertificateFile) > 0 {
		peerCert = gcrypto.CreateCryptoObject().GetRSA(config.PeerCertificateFile, "")
		if peerCert == nil {
			return nil, errors.New("invalid peer certificate")
		}
	}

	//
	localTS, err := thisPt.createTrafficSelector(config.LocalNetwork)
	if err != nil {
		return nil, err
	}

	remoteTS, err := thisPt.createTrafficSelector(config.RemoteNetwork)
	if err != nil {
		return nil, err
	}

	//process phase1 info
	phase1Info, err := thisPt.getProposalInfo(config.Phase1Info)
	if err != nil {
		return nil, fmt.Errorf("error parsing phase1 parameters, %s", err)
	}

	//process phase2 info
	phase2Info, err := thisPt.getProposalInfo(config.Phase2Info)
	if err != nil {
		return nil, fmt.Errorf("error parsing phase2 parameters, %s", err)
	}

	//initialize profile object
	profile := ike.IKEProfile{
		HalfOpenSessionsLifeTime: config.HalfOpenSessionsLifeTime,
		InactiveSessionsLifeTime: config.InactiveSessionsLifeTime,
		RemovedSessionsLifeTime:  config.RemovedSessionsLifeTime,
		EnableTransport:          false,
		EnableNat:                true,
		EnableFragment:           true,
		CA:                       ca,
		Certificate:              cert,
		PrivateKey:               pkey,
		PeerCertificate:          peerCert,
		VendorID:                 "goke",
		PSK:                      config.PSK,
		UsePSK:                   (len(config.PSK) > 1),
		FQDN:                     config.FQDN,
		LocalTS:                  localTS,
		RemoteTS:                 remoteTS,
		Phase1Proposal:           phase1Info,
		Phase2Proposal:           phase2Info,
		Cookie:                   nil,
	}

	//
	return ike.CreateIKE(nil, &profile), nil
}

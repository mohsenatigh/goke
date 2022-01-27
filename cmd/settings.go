package main

import (
	"github.com/mohsenatigh/goke/gcrypto"
	"github.com/mohsenatigh/goke/ikeserver"
)

//---------------------------------------------------------------------------------------
type Settings struct {
	UDPServer ikeserver.IKEServerUDPConfig `json:"udp_server"`
}

//---------------------------------------------------------------------------------------
func (thisPt *Settings) InitDefault() {
	thisPt.UDPServer.ListenIP = "0.0.0.0"
	thisPt.UDPServer.ListenPort = 500
	thisPt.UDPServer.ListenPort = 4500
	thisPt.UDPServer.IKEConfig.HalfOpenSessionsLifeTime = 10
	thisPt.UDPServer.IKEConfig.InactiveSessionsLifeTime = 3600
	thisPt.UDPServer.IKEConfig.LocalNetwork = "10.0.0.1/24"
	thisPt.UDPServer.IKEConfig.RemoteNetwork = "10.0.0.1/24"
	thisPt.UDPServer.IKEConfig.PSK = "123456"
	thisPt.UDPServer.IKEConfig.Phase1Info = gcrypto.GetDefaultIKEAlgorithmString()
	thisPt.UDPServer.IKEConfig.Phase2Info = gcrypto.GetDefaultESPAlgorithmString()
}

//---------------------------------------------------------------------------------------
func (thisPt *Settings) Load() error {
	return nil
}

//---------------------------------------------------------------------------------------

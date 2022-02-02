package main

import (
	"encoding/json"
	"io/ioutil"

	"github.com/mohsenatigh/goke/gcrypto"
	"github.com/mohsenatigh/goke/ikeserver"
	"github.com/mohsenatigh/goke/objectmodel"
)

//---------------------------------------------------------------------------------------
type Settings struct {
	UDPServerEnable bool                         `json:"udp_server_enable"`
	UDPServer       ikeserver.IKEServerUDPConfig `json:"udp_server"`
}

//---------------------------------------------------------------------------------------
func (thisPt *Settings) initDefault() {
	thisPt.UDPServerEnable = true
	thisPt.UDPServer.ListenIP = "0.0.0.0"
	thisPt.UDPServer.ListenPort = 500
	thisPt.UDPServer.ListenPortNat = 4500
	thisPt.UDPServer.IKEConfig.HalfOpenSessionsLifeTime = 10
	thisPt.UDPServer.IKEConfig.InactiveSessionsLifeTime = 3600
	thisPt.UDPServer.IKEConfig.RemovedSessionsLifeTime = 10
	thisPt.UDPServer.IKEConfig.LocalNetwork = "10.0.0.0-10.0.0.254"
	thisPt.UDPServer.IKEConfig.RemoteNetwork = "10.0.0.0-10.0.0.254"
	thisPt.UDPServer.IKEConfig.PSK = "123456"
	thisPt.UDPServer.IKEConfig.Phase1Info = gcrypto.GetDefaultIKEAlgorithmString()
	thisPt.UDPServer.IKEConfig.Phase2Info = gcrypto.GetDefaultESPAlgorithmString()
}

//---------------------------------------------------------------------------------------
func (thisPt *Settings) load(fileName string) error {

	//
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return err
	}

	//
	if err := json.Unmarshal(data, thisPt); err != nil {
		return err
	}

	//validate
	if err := objectmodel.ValidateObject(*thisPt); err != nil {
		return err
	}

	return nil
}

//---------------------------------------------------------------------------------------
func loadSettings(path string) (*Settings, error) {
	st := &Settings{}

	st.initDefault()
	if err := st.load(path); err != nil {
		return nil, err
	}
	return st, nil
}

//---------------------------------------------------------------------------------------
func loadDefaultSettings() *Settings {
	st := &Settings{}
	st.initDefault()
	return st
}

//---------------------------------------------------------------------------------------

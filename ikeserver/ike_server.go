package ikeserver

import "github.com/mohsenatigh/goke/ike"

//---------------------------------------------------------------------------------------
type IKEServerIKEConfig struct {
	HalfOpenSessionsLifeTime int64  `json:"half_open_sessions_life_time" validate:"min=10,max=60"`
	InactiveSessionsLifeTime int64  `json:"inactive_sessions_life_time" validate:"min=60,max=3600"`
	RemovedSessionsLifeTime  int64  `json:"removed_sessions_life_time" validate:"min=2,max=30"`
	CaFile                   string `json:"ca"  validate:"omitempty,file"`
	CertificateFile          string `json:"certificate" validate:"omitempty,file"`
	PrivateKeyFile           string `json:"privatekey" validate:"omitempty,file"`
	PeerCertificateFile      string `json:"peer_certificate" validate:"omitempty,file"`
	PSK                      string `json:"psk" validate:"omitempty,alphanum,min=6,max=40"`
	FQDN                     string `json:"fqdn" validate:"omitempty,alphanum,min=6,max=40"`
	LocalNetwork             string `json:"local_network" validate:"omitempty,iprange"`
	RemoteNetwork            string `json:"remote_network" validate:"omitempty,iprange"`
	Phase1Info               string `json:"phase1_info" validate:"algorithm"`
	Phase2Info               string `json:"phase2_info" validate:"algorithm"`
}

//---------------------------------------------------------------------------------------
type IServerActor interface {
	InstallESP(context ike.IIKEProcessContext)
	RemoveESP(context ike.IIKEProcessContext)
}

//---------------------------------------------------------------------------------------
type IServer interface {
	Stop()
}

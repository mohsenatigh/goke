package ikeserver

import "github.com/mohsenatigh/goke/ike"

//---------------------------------------------------------------------------------------
type IKEServerIKEConfig struct {
	HalfOpenSessionsLifeTime int64  `json:"half_open_sessions_life_time" validate:"min=10,max=60"`
	InactiveSessionsLifeTime int64  `json:"inactive_sessions_life_time" validate:"min=60,max=3600"`
	RemovedSessionsLifeTime  int64  `json:"removed_sessions_life_time" validate:"min=2,max=30"`
	CaFile                   string `json:"ca"  validate:"file,omitempty"`
	CertificateFile          string `json:"certificate" validate:"file,omitempty"`
	PrivateKeyFile           string `json:"privatekey" validate:"file,omitempty"`
	PeerCertificateFile      string `json:"peer_certificate" validate:"file,omitempty"`
	PSK                      string `json:"psk" validate:"alphanum,min=6,max=40,omitempty"`
	FQDN                     string `json:"fqdn" validate:"alphanum,min=6,max=40,omitempty"`
	LocalNetwork             string `json:"local_network" validate:"omitempty,cidr"`
	RemoteNetwork            string `json:"remote_network" validate:"omitempty,cidr"`
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

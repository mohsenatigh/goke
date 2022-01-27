package ike

import "net"

//
type ikeContext struct {
	nat     bool
	local   *net.UDPAddr
	remote  *net.UDPAddr
	profile *IKEProfile
	session IIKESession
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeContext) RemoteAddress() *net.UDPAddr {
	return thisPt.remote
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeContext) LocalAddress() *net.UDPAddr {
	return thisPt.local
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeContext) Nat() bool {
	return thisPt.nat
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeContext) GetProfile() IKEProfile {
	return *thisPt.profile
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeContext) GetSession() IIKESession {
	return thisPt.session
}

//---------------------------------------------------------------------------------------
func createIKEContext(local, remote *net.UDPAddr, nat bool, profile *IKEProfile, session IIKESession) IIKEProcessContext {
	return &ikeContext{
		nat:     nat,
		local:   local,
		remote:  remote,
		profile: profile,
		session: session,
	}
}

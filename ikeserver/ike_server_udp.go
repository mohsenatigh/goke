package ikeserver

import (
	"fmt"
	"log"
	"net"

	"github.com/mohsenatigh/goke/ike"
)

const max_PACKET_SIZE = 2048

//---------------------------------------------------------------------------------------
type IKEServerUDPConfig struct {
	ListenIP      string             `json:"listen_ip"`
	ListenPort    int                `json:"listen_port"`
	ListenPortNat int                `json:"nat_port"`
	IKEConfig     IKEServerIKEConfig `json:"ike"`
	Actor         IServerActor       `json:"-"`
}

//---------------------------------------------------------------------------------------
type ikeServerUDP struct {
	ikeServerBase
	config       IKEServerUDPConfig
	ikeProcessor ike.IIKE
	udpCon       *net.UDPConn
	udpNatCon    *net.UDPConn
	isActive     bool
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeServerUDP) send(buffer []byte, remote *net.UDPAddr, nat bool) {
	connection := thisPt.udpCon
	if nat {
		connection = thisPt.udpNatCon
	}

	if _, err := connection.WriteTo(buffer, remote); err != nil {
		log.Printf("ike packet process failed with error %s", err.Error())
	}
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeServerUDP) processPackets(buffer []byte, local *net.UDPAddr, remote *net.UDPAddr, nat bool) {
	//check connection
	out, err := thisPt.ikeProcessor.Process(buffer, nat, local, remote)
	if err != nil {
		log.Printf("ike packet process failed with error %s", err.Error())
	}

	//check buffer
	if out != nil {
		thisPt.send(out, remote, nat)
	}
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeServerUDP) readPackets(con *net.UDPConn, nat bool) {
	//
	buffer := [max_PACKET_SIZE]byte{}
	for thisPt.isActive {
		//
		len, remote, err := con.ReadFrom(buffer[:])
		if len < 1 || err != nil {
			continue
		}

		//
		localAddr := con.LocalAddr().(*net.UDPAddr)
		remoteAddr := remote.(*net.UDPAddr)
		thisPt.processPackets(buffer[:], localAddr, remoteAddr, nat)
	}
	con.Close()
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeServerUDP) listen() error {

	udpAddr := net.UDPAddr{
		IP:   net.ParseIP(thisPt.config.ListenIP),
		Port: thisPt.config.ListenPort,
	}

	//
	if udpAddr.IP == nil {
		return fmt.Errorf("invalid IP address %s", thisPt.config.ListenIP)
	}

	//setup command server
	commandServer, err := net.ListenUDP("udp", &udpAddr)
	if err != nil {
		return err
	}

	//setup NAT server
	udpAddr.Port = thisPt.config.ListenPortNat
	natServer, err := net.ListenUDP("udp", &udpAddr)
	if err != nil {
		return err
	}

	//
	thisPt.udpCon = commandServer
	thisPt.udpNatCon = natServer

	//create IKE processor
	thisPt.ikeProcessor, err = thisPt.createIKEInstance(&thisPt.config.IKEConfig)
	if err != nil {
		return err
	}

	//read packets
	go thisPt.readPackets(commandServer, false)
	go thisPt.readPackets(natServer, true)
	return nil
}

//---------------------------------------------------------------------------------------
//for IIKEActor
func (thisPt *ikeServerUDP) InstallESP(context ike.IIKEProcessContext) {
	if thisPt.config.Actor != nil {
		thisPt.config.Actor.InstallESP(context)
	}
}

//---------------------------------------------------------------------------------------
//for IIKEActor
func (thisPt *ikeServerUDP) RemoveESP(context ike.IIKEProcessContext) {
	if thisPt.config.Actor != nil {
		thisPt.config.Actor.RemoveESP(context)
	}
}

//---------------------------------------------------------------------------------------
//for IIKEActor
func (thisPt *ikeServerUDP) SendControlData(data []byte, context ike.IIKEProcessContext) {
	thisPt.send(data, context.RemoteAddress(), context.Nat())
}

//---------------------------------------------------------------------------------------
//for IServer
func (thisPt *ikeServerUDP) Stop() {
	thisPt.isActive = false
}

//---------------------------------------------------------------------------------------

func CreateServerUDP(config *IKEServerUDPConfig) (IServer, error) {
	server := &ikeServerUDP{
		config:   *config,
		isActive: true,
	}

	if err := server.listen(); err != nil {
		return nil, err
	}

	return server, nil
}

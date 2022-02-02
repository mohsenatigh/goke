package main

import (
	"context"
	"log"
	"os"
	"sync"

	"github.com/mohsenatigh/goke/ikeserver"
)

//---------------------------------------------------------------------------------------
type server struct {
	set       *Settings
	udpServer ikeserver.IServer
}

//---------------------------------------------------------------------------------------
func (thisPt *server) startUDPServer(ctx context.Context, waitGroup *sync.WaitGroup) {
	//
	if !thisPt.set.UDPServerEnable {
		return
	}

	waitGroup.Add(1)
	defer waitGroup.Done()

	//create server and wait for context termination
	s, err := ikeserver.CreateServerUDP(&thisPt.set.UDPServer)
	if err != nil {
		log.Printf("can not start ike udp server with error %s \n", err)
		os.Exit(0)
	}
	log.Printf("ike udp server started successfully")
	thisPt.udpServer = s

	<-ctx.Done()

	//s.Stop()
	log.Printf("ike udp server stopped successfully")
}

//---------------------------------------------------------------------------------------
func (thisPt *server) start(ctx context.Context, waitGroup *sync.WaitGroup) {
	//other server come here
	go thisPt.startUDPServer(ctx, waitGroup)
}

//---------------------------------------------------------------------------------------
func startServer(ctx context.Context, waitGroup *sync.WaitGroup, set *Settings) {
	s := &server{set: set}
	s.start(ctx, waitGroup)
}

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/mohsenatigh/goke/ike"
)

//---------------------------------------------------------------------------------------
func handleSignals() {
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	s := <-sigc
	log.Printf("receive signal %v \n", s)
}

//---------------------------------------------------------------------------------------
func startComponents(set *Settings) {
	pctx := context.Background()
	ctx, cancelFunc := context.WithCancel(pctx)
	waitGroup := sync.WaitGroup{}
	//start servers
	startServer(ctx, &waitGroup, set)

	//wait for signals
	handleSignals()

	//signal routins
	cancelFunc()

	//wait for termination
	waitGroup.Wait()
}

//---------------------------------------------------------------------------------------
func main() {

	st := flag.String("f", "", "static configuration")
	version := flag.Bool("version", false, "")

	flag.Parse()

	//check for version
	if *version {
		fmt.Printf("%s\n", ike.IKE_VERSION)
		return
	}

	//
	set, err := loadSettings(*st)
	if err != nil {
		log.Printf("can not load settings with error [%s]. switching to default values\n", err)
		set = loadDefaultSettings()
	}
	startComponents(set)
}

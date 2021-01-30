package server

import (
	"log"
	"testing"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/interactsh/pkg/storage"
)

func TestDNSServer(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)

	server, err := NewDNSServer(&Options{
		Storage:   storage.New(10 * time.Minute),
		Domain:    "interact.sh.",
		IPAddress: "192.168.1.1",
	})
	if err != nil {
		log.Fatalf("%s\n", err)
	}
	server.ListenAndServe()

	time.Sleep(10 * time.Minute)
}

package server

import (
	"testing"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/interactsh/pkg/storage"
	"github.com/stretchr/testify/require"
)

func TestHTTPServerListen(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)

	server, err := NewHTTPServer(&Options{
		Storage: storage.New(10 * time.Minute),
	})
	require.Nil(t, err, "could not create http server")

	server.ListenAndServe()

	time.Sleep(10 * time.Minute)
}

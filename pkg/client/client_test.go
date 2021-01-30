package client

import (
	"fmt"
	"os"
	"os/signal"
	"testing"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/stretchr/testify/require"
)

func TestClient(t *testing.T) {
	client, err := New(&Options{"https://interact.sh", false})
	require.Nil(t, err, "could not create client")

	fmt.Printf("URL: %s\n", client.URL())

	client.StartPolling(5*time.Second, func(interaction *server.Interaction) {
		fmt.Printf("%+v\n", interaction)
	})

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	for range c {
		client.StopPolling()
		client.Close()
		os.Exit(1)
	}
}

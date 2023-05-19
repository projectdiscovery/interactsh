package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"
)

func main() {
	client, err := client.New(client.DefaultOptions)
	if err != nil {
		panic(err)
	}
	defer client.Close()

	client.StartPolling(time.Duration(1*time.Second), func(interaction *server.Interaction) {
		fmt.Printf("Got Interaction: %v => %v\n", interaction.Protocol, interaction.FullId)
	})
	defer client.StopPolling()

	URL := client.URL()

	resp, err := http.Get("https://" + URL)
	if err != nil {
		panic(err)
	}
	resp.Body.Close()

	fmt.Printf("Got URL: %v => %v\n", URL, resp)
	time.Sleep(1 * time.Second)
}

package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"
)

func main() {
	// Named c rather than client so the package stays reachable for its
	// exported errors below.
	c, err := client.New(client.DefaultOptions)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := c.Close(); err != nil {
			panic(err)
		}
	}()

	if err := c.StartPolling(time.Duration(1*time.Second), func(interaction *server.Interaction) {
		fmt.Printf("Got Interaction: %v => %v\n", interaction.Protocol, interaction.FullId)
	}); err != nil {
		panic(err)
	}
	defer func() {
		if err := c.StopPolling(); err != nil {
			panic(err)
		}
	}()

	URL := c.URL()

	resp, err := http.Get("https://" + URL)
	if err != nil {
		panic(err)
	}
	if err := resp.Body.Close(); err != nil {
		panic(err)
	}

	fmt.Printf("Got URL: %v => %v\n", URL, resp)

	// Second stage: host a file against this session, if the server offers it.
	hostFile(c, URL)

	time.Sleep(1 * time.Second)
}

// hostFile uploads a file and fetches it back, which is how a second-stage
// payload is verified: the target retrieves the hosted file, and that retrieval
// arrives as an interaction of its own.
//
// Hosting is optional, so a caller has to handle its absence. The server
// advertises it at registration, and the public oast.* servers deliberately do
// not offer it, so this returns quietly rather than failing.
func hostFile(c *client.Client, payloadHost string) {
	caps := c.Capabilities()
	switch {
	case caps == nil && c.CapabilitiesKnown():
		// The server answered and said nothing about capabilities, so it
		// predates file hosting.
		fmt.Println("Hosting: server predates file hosting, skipping")
		return
	case caps != nil && !caps.Upload:
		fmt.Println("Hosting: server does not offer file hosting, skipping")
		return
	}
	// caps == nil with nothing known -- a resumed session, say -- falls through:
	// the only way to find out is to ask, and UploadFiles reports what it learns.

	path, err := writeTempFile(`<!ENTITY % exfil SYSTEM "file:///etc/hostname">`)
	if err != nil {
		fmt.Printf("Hosting: %v\n", err)
		return
	}
	defer func() { _ = os.Remove(path) }()

	files, err := c.UploadFiles([]string{path})
	if err != nil {
		// Distinguishable so a caller can tell "cannot host" from "the request
		// failed", and act on the right one.
		switch {
		case errors.Is(err, client.ErrUploadNotAdvertised):
			fmt.Println("Hosting: server predates file hosting, skipping")
		case errors.Is(err, client.ErrUploadUnsupported):
			fmt.Println("Hosting: server does not offer file hosting, skipping")
		default:
			fmt.Printf("Hosting: upload failed: %v\n", err)
		}
		return
	}

	for _, file := range files {
		// Any host from URL() works: the server reads only its correlation ID.
		fileURL := c.FileURL(payloadHost, file)
		fmt.Printf("Hosting %s (%d bytes, sha256 %s) => %s\n", file.Name, file.Size, file.SHA256, fileURL)
		if caps != nil && caps.FTP {
			fmt.Printf("Hosting %s over FTP => %s\n", file.Name, c.FTPFileURL(payloadHost, file))
		}

		// Stand in for the target fetching it; the fetch is recorded as an
		// interaction against this session and arrives in the poll callback.
		resp, err := http.Get(fileURL)
		if err != nil {
			fmt.Printf("Hosting: could not fetch %s: %v\n", fileURL, err)
			continue
		}
		if err := resp.Body.Close(); err != nil {
			panic(err)
		}
		fmt.Printf("Fetched %s => %v\n", fileURL, resp.Status)
	}
}

func writeTempFile(content string) (string, error) {
	f, err := os.CreateTemp("", "interactsh-example-*.dtd")
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(content); err != nil {
		return "", err
	}
	return f.Name(), nil
}

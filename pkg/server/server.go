package server

import (
	"strings"

	"github.com/projectdiscovery/interactsh/pkg/storage"
)

// Interaction is an interaction recieved to the server.
type Interaction struct {
	// Protocol for interaction, can contains HTTP/DNS/SMTP,etc.
	Protocol string `json:"protocol"`
	// UniqueID is the uniqueID for the subdomain recieving the interaction.
	UniqueID string `json:"unique-id"`
}

// Options contains configuration options for the servers
type Options struct {
	// CACert is the CA certificate for TLS servers
	CACert string
	// CAKey is the CA key for TLS servers
	CAKey string
	// Storage is a storage for interaction data storage
	Storage *storage.Storage
}

// URLReflection returns a reversed part of the URL payload
// which is checked in theb
func URLReflection(URL string) string {
	parts := strings.Split(URL, ".")
	var randomID string
	for _, part := range parts {
		if len(part) == 32 {
			randomID = part
		}
	}
	rns := []rune(randomID)
	for i, j := 0, len(rns)-1; i < j; i, j = i+1, j-1 {
		rns[i], rns[j] = rns[j], rns[i]
	}
	return string(rns)
}

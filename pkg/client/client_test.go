package client

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClient(t *testing.T) {
	client, err := New(&Options{"http://localhost:8082"})
	require.Nil(t, err, "could not create client")

	for i := 0; i < 10; i++ {
		fmt.Printf("URL: %s\n", client.URL())
	}
}

package storage

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/gob"
	"testing"
	"time"

	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
)

func TestStorageSetIDPublicKey(t *testing.T) {
	storage := New(1 * time.Hour)

	correlationID := xid.New().String()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.Nil(t, err, "could not generate rsa key")

	buffer := &bytes.Buffer{}
	err = gob.NewEncoder(buffer).Encode(privateKey.Public())
	require.Nil(t, err, "could not encode rsa public key")

	err = storage.SetIDPublicKey(correlationID, buffer.Bytes())
	require.Nil(t, err, "could not set correlation-id and rsa public key in storage")

	item := storage.cache.Get(correlationID)
	require.NotNil(t, item, "could not get correlation-id item from storage")

	value, ok := item.Value().(*CorrelationData)
	require.True(t, ok, "could not assert item value type as correlation data")

	require.Equal(t, &privateKey.PublicKey, value.publicKey, "could not get correct public key")
}

func TestStorageAddGetInteractions(t *testing.T) {
	storage := New(1 * time.Hour)

	correlationID := xid.New().String()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.Nil(t, err, "could not generate rsa key")

	buffer := &bytes.Buffer{}
	err = gob.NewEncoder(buffer).Encode(privateKey.Public())
	require.Nil(t, err, "could not encode rsa public key")

	err = storage.SetIDPublicKey(correlationID, "test", buffer.Bytes())
	require.Nil(t, err, "could not set correlation-id and rsa public key in storage")

	dataOriginal := []byte("hello world, this is unencrypted interaction")
	err = storage.AddInteraction(correlationID, dataOriginal)
	require.Nil(t, err, "could not add interaction to storage")

	data, err := storage.GetInteractions(correlationID, "test")
	require.Nil(t, err, "could not get interaction from storage")

	plaintext, err := privateKey.Decrypt(nil, data[0], &rsa.OAEPOptions{Hash: crypto.SHA256})
	require.Nil(t, err, "could not decrypt encrypted interaction data")

	require.Equal(t, dataOriginal, plaintext, "could not get correct decrypted interaction")
}

package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
)

func TestStorageSetIDPublicKey(t *testing.T) {
	storage := New(1 * time.Hour)

	secret := uuid.New().String()
	correlationID := xid.New().String()

	// Generate a 2048-bit private-key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.Nil(t, err, "could not generate rsa key")

	pub := priv.Public()

	pubkeyBytes, err := x509.MarshalPKIXPublicKey(pub)
	require.Nil(t, err, "could not marshal public key")

	pubkeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubkeyBytes,
	})

	encoded := base64.StdEncoding.EncodeToString(pubkeyPem)

	err = storage.SetIDPublicKey(correlationID, secret, encoded)
	require.Nil(t, err, "could not set correlation-id and rsa public key in storage")

	item := storage.cache.Get(correlationID)
	require.NotNil(t, item, "could not get correlation-id item from storage")

	value, ok := item.Value().(*CorrelationData)
	require.True(t, ok, "could not assert item value type as correlation data")

	require.Equal(t, secret, value.secretKey, "could not get correct secret key")
}

func TestStorageAddGetInteractions(t *testing.T) {
	storage := New(1 * time.Hour)

	secret := uuid.New().String()
	correlationID := xid.New().String()

	// Generate a 2048-bit private-key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.Nil(t, err, "could not generate rsa key")

	pub := priv.Public()

	pubkeyBytes, err := x509.MarshalPKIXPublicKey(pub)
	require.Nil(t, err, "could not marshal public key")

	pubkeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubkeyBytes,
	})

	// Decode and get the first block in the PEM file.
	// In our case it should be the Public key block.
	pemBlock, _ := pem.Decode([]byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnX9FrceoIYvZn2rpOQXK
zM6VVCURKVKuKaZEUST2hQD3S2TLQL7QrAZe2U4ME4oGqU6z0m0uLgOrCmQ7uwWC
3x3wPMQPZE717T0SlGyp/FKs4AK+Wh2UQHGEnvXwdulTN1XgsVLSg+bwNlE0u7Nj
7zyb+XNeryzuM73xC6YEC7V1Md6fvmL6yk9QK8iLEWf9aXpU1ErTAd5TIKJ05XQ6
WdUYTfZI5vPhUur9raTJVGeWgphGN7LPHmCLbx/vu3iS8UoZ9U4l6/7NeskVXxyT
RXlCsV8ZYZce6TF51p+g+47HewoKpV1xFoqPMQPJK3uDEjr8mkLIs4RPXfMp75mh
9wIDAQAB
-----END PUBLIC KEY-----`))
	require.Nil(t, err, "could not marshal public key")

	// Convert to rsa
	rsaPubKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	require.Nil(t, err, "could not marshal public key")

	// Confirm we got an rsa public key. Returned value is an interface{}
	sshKey, _ := rsaPubKey.(*rsa.PublicKey)
	require.Nil(t, err, "could not marshal public key")

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, sshKey, []byte("this is a test"), []byte(""))
	require.Nil(t, err, "could not marshal public key")

	fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(ciphertext))
	encoded := base64.StdEncoding.EncodeToString(pubkeyPem)

	err = storage.SetIDPublicKey(correlationID, secret, encoded)
	require.Nil(t, err, "could not set correlation-id and rsa public key in storage")

	dataOriginal := []byte("hello world, this is unencrypted interaction")
	err = storage.AddInteraction(correlationID, dataOriginal)
	require.Nil(t, err, "could not add interaction to storage")

	data, key, err := storage.GetInteractions(correlationID, secret)
	require.Nil(t, err, "could not get interaction from storage")

	decodedKey, err := base64.StdEncoding.DecodeString(key)
	require.Nil(t, err, "could not decode key")

	// Decrypt the key plaintext first
	keyPlaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, decodedKey, nil)
	require.Nil(t, err, "could not decrypt key to plaintext")

	cipherText, err := base64.StdEncoding.DecodeString(data[0])
	require.Nil(t, err, "could not decode ciphertext")

	block, err := aes.NewCipher(keyPlaintext)
	require.Nil(t, err, "could not create aes cipher")

	if len(cipherText) < aes.BlockSize {
		require.Fail(t, "Cipher text is less than block size")
	}

	// IV is at the start of the Ciphertext
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	// XORKeyStream can work in-place if the two arguments are the same.
	stream := cipher.NewCFBDecrypter(block, iv)
	decoded := make([]byte, len(cipherText))
	stream.XORKeyStream(decoded, cipherText)

	require.Equal(t, dataOriginal, decoded, "could not get correct decrypted interaction")
}

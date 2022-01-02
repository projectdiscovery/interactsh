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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goburrow/cache"
	"github.com/google/uuid"
	"github.com/karlseguin/ccache/v2"
	"github.com/klauspost/compress/zlib"
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

	item, ok := storage.cache.GetIfPresent(correlationID)
	require.True(t, ok, "could not assert item value presence")
	require.NotNil(t, item, "could not get correlation-id item from storage")

	value, ok := item.(*CorrelationData)
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

func TestGetInteractions(t *testing.T) {
	compressZlib := func(data string) string {
		var builder strings.Builder
		writer := zlib.NewWriter(&builder)
		_, _ = writer.Write([]byte(data))
		writer.Close()
		return builder.String()
	}
	data := &CorrelationData{
		dataMutex: &sync.Mutex{},
		Data:      []string{compressZlib("test"), compressZlib("another")},
	}
	decompressed := data.GetInteractions()
	require.ElementsMatch(t, []string{"test", "another"}, decompressed, "could not get correct decompressed list")
}

func BenchmarkCacheParallel(b *testing.B) {
	config := ccache.Configure().MaxSize(defaultCacheMaxSize).Buckets(64).GetsPerPromote(10).PromoteBuffer(4096)
	cache := ccache.New(config)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			doStuffWithCache(cache)
		}
	})
}

func BenchmarkCacheParallelOther(b *testing.B) {
	cache := cache.New(cache.WithMaximumSize(defaultCacheMaxSize), cache.WithExpireAfterWrite(24*7*time.Hour))

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			doStuffWithOtherCache(cache)
		}
	})
}

func doStuffWithCache(cache *ccache.Cache) {
	for i := 0; i < 1e2; i++ {
		cache.Set(strconv.Itoa(i), "test", 1*time.Minute)
		_ = cache.Get(strconv.Itoa(i))
	}
}

func doStuffWithOtherCache(cache cache.Cache) {
	for i := 0; i < 1e2; i++ {
		cache.Put(strconv.Itoa(i), "test")
		_, _ = cache.GetIfPresent(strconv.Itoa(i))
	}
}

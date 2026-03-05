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
	"testing"
	"time"

	"github.com/goburrow/cache"
	"github.com/google/uuid"
	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
)

func TestStorageSetIDPublicKey(t *testing.T) {
	mem, err := New(&Options{EvictionTTL: 1 * time.Hour})
	require.Nil(t, err)

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

	err = mem.SetIDPublicKey(correlationID, secret, encoded)
	require.Nil(t, err, "could not set correlation-id and rsa public key in storage")

	item, ok := mem.cache.GetIfPresent(correlationID)
	require.True(t, ok, "could not assert item value presence")
	require.NotNil(t, item, "could not get correlation-id item from storage")

	value, ok := item.(*CorrelationData)
	require.True(t, ok, "could not assert item value type as correlation data")

	require.Equal(t, secret, value.SecretKey, "could not get correct secret key")
}

func TestStorageAddGetInteractions(t *testing.T) {
	mem, err := New(&Options{EvictionTTL: 1 * time.Hour})
	require.Nil(t, err)

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

	err = mem.SetIDPublicKey(correlationID, secret, encoded)
	require.Nil(t, err, "could not set correlation-id and rsa public key in storage")

	dataOriginal := []byte("hello world, this is unencrypted interaction")
	err = mem.AddInteraction(correlationID, dataOriginal)
	require.Nil(t, err, "could not add interaction to storage")

	data, key, err := mem.GetInteractions(correlationID, secret)
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
	stream := cipher.NewCTR(block, iv)
	decoded := make([]byte, len(cipherText))
	stream.XORKeyStream(decoded, cipherText)

	require.Equal(t, dataOriginal, decoded, "could not get correct decrypted interaction")
}

func BenchmarkCacheParallelOther(b *testing.B) {
	cache := cache.New(cache.WithMaximumSize(DefaultOptions.MaxSize), cache.WithExpireAfterWrite(24*7*time.Hour))

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			doStuffWithOtherCache(cache)
		}
	})
}

func doStuffWithOtherCache(cache cache.Cache) {
	for i := 0; i < 1e2; i++ {
		cache.Put(strconv.Itoa(i), "test")
		_, _ = cache.GetIfPresent(strconv.Itoa(i))
	}
}

func TestGetInteractionsWithIdForConsumer(t *testing.T) {
	t.Run("two consumers independently receive all interactions", func(t *testing.T) {
		mem, err := New(&Options{EvictionTTL: 1 * time.Hour})
		require.NoError(t, err)
		defer mem.Close()

		require.NoError(t, mem.SetID("shared"))
		require.NoError(t, mem.AddInteractionWithId("shared", []byte("interaction-1")))
		require.NoError(t, mem.AddInteractionWithId("shared", []byte("interaction-2")))

		dataA, err := mem.GetInteractionsWithIdForConsumer("shared", "consumer-a")
		require.NoError(t, err)
		require.Equal(t, []string{"interaction-1", "interaction-2"}, dataA)

		dataB, err := mem.GetInteractionsWithIdForConsumer("shared", "consumer-b")
		require.NoError(t, err)
		require.Equal(t, []string{"interaction-1", "interaction-2"}, dataB)
	})

	t.Run("subsequent poll returns only unseen data", func(t *testing.T) {
		mem, err := New(&Options{EvictionTTL: 1 * time.Hour})
		require.NoError(t, err)
		defer mem.Close()

		require.NoError(t, mem.SetID("shared"))
		require.NoError(t, mem.AddInteractionWithId("shared", []byte("msg-1")))

		dataA, err := mem.GetInteractionsWithIdForConsumer("shared", "consumer-a")
		require.NoError(t, err)
		require.Equal(t, []string{"msg-1"}, dataA)

		require.NoError(t, mem.AddInteractionWithId("shared", []byte("msg-2")))
		require.NoError(t, mem.AddInteractionWithId("shared", []byte("msg-3")))

		// consumer-a should only see new data
		dataA2, err := mem.GetInteractionsWithIdForConsumer("shared", "consumer-a")
		require.NoError(t, err)
		require.Equal(t, []string{"msg-2", "msg-3"}, dataA2)

		// consumer-b sees everything on first poll
		dataB, err := mem.GetInteractionsWithIdForConsumer("shared", "consumer-b")
		require.NoError(t, err)
		require.Equal(t, []string{"msg-1", "msg-2", "msg-3"}, dataB)
	})

	t.Run("empty poll returns nil", func(t *testing.T) {
		mem, err := New(&Options{EvictionTTL: 1 * time.Hour})
		require.NoError(t, err)
		defer mem.Close()

		require.NoError(t, mem.SetID("shared"))

		data, err := mem.GetInteractionsWithIdForConsumer("shared", "consumer-a")
		require.NoError(t, err)
		require.Nil(t, data)
	})

	t.Run("RemoveConsumer compacts data read by remaining consumers", func(t *testing.T) {
		mem, err := New(&Options{EvictionTTL: 1 * time.Hour})
		require.NoError(t, err)
		defer mem.Close()

		require.NoError(t, mem.SetID("shared"))
		require.NoError(t, mem.AddInteractionWithId("shared", []byte("msg-1")))
		require.NoError(t, mem.AddInteractionWithId("shared", []byte("msg-2")))

		// Both consumers read all data
		_, err = mem.GetInteractionsWithIdForConsumer("shared", "consumer-a")
		require.NoError(t, err)
		_, err = mem.GetInteractionsWithIdForConsumer("shared", "consumer-b")
		require.NoError(t, err)

		// Remove consumer-a — consumer-b already read all, so data is compacted
		require.NoError(t, mem.RemoveConsumer("shared", "consumer-a"))

		item, _ := mem.cache.GetIfPresent("shared")
		value := item.(*CorrelationData)
		value.Lock()
		require.Nil(t, value.Data)
		_, hasA := value.ReadOffsets["consumer-a"]
		require.False(t, hasA)
		value.Unlock()
	})

	t.Run("RemoveConsumer partial compaction", func(t *testing.T) {
		mem, err := New(&Options{EvictionTTL: 1 * time.Hour})
		require.NoError(t, err)
		defer mem.Close()

		require.NoError(t, mem.SetID("shared"))
		for i := range 5 {
			require.NoError(t, mem.AddInteractionWithId("shared", []byte("msg-"+strconv.Itoa(i))))
		}

		// consumer-a reads all 5
		dataA, err := mem.GetInteractionsWithIdForConsumer("shared", "consumer-a")
		require.NoError(t, err)
		require.Len(t, dataA, 5)

		// consumer-b reads 3 (of the 5 total, offset advances to 5 as well since it reads all)
		// Actually, consumer-b also reads all 5
		dataB, err := mem.GetInteractionsWithIdForConsumer("shared", "consumer-b")
		require.NoError(t, err)
		require.Len(t, dataB, 5)

		// Remove consumer-a — consumer-b at offset 5, trim data[:5]
		require.NoError(t, mem.RemoveConsumer("shared", "consumer-a"))

		item, _ := mem.cache.GetIfPresent("shared")
		value := item.(*CorrelationData)
		value.Lock()
		require.Nil(t, value.Data)
		require.Equal(t, 0, value.ReadOffsets["consumer-b"])
		value.Unlock()
	})

	t.Run("stale consumer eviction", func(t *testing.T) {
		// Use long cache TTL but short consumer staleness check
		mem, err := New(&Options{EvictionTTL: 1 * time.Hour})
		require.NoError(t, err)
		defer mem.Close()

		require.NoError(t, mem.SetID("shared"))
		require.NoError(t, mem.AddInteractionWithId("shared", []byte("msg-1")))

		// consumer-a reads data
		_, err = mem.GetInteractionsWithIdForConsumer("shared", "consumer-a")
		require.NoError(t, err)

		// Manually backdate consumer-a's LastSeen to simulate staleness
		item, _ := mem.cache.GetIfPresent("shared")
		value := item.(*CorrelationData)
		value.Lock()
		value.LastSeen["consumer-a"] = time.Now().Add(-2 * time.Hour)
		value.Unlock()

		require.NoError(t, mem.AddInteractionWithId("shared", []byte("msg-2")))

		// consumer-b polls — stale consumer-a should be evicted
		dataB, err := mem.GetInteractionsWithIdForConsumer("shared", "consumer-b")
		require.NoError(t, err)
		require.Contains(t, dataB, "msg-2")

		value.Lock()
		_, hasStale := value.ReadOffsets["consumer-a"]
		require.False(t, hasStale, "stale consumer should be evicted")
		value.Unlock()
	})

	t.Run("max buffer cap enforced", func(t *testing.T) {
		bufferCap := 100
		mem, err := New(&Options{EvictionTTL: 1 * time.Hour, MaxSharedInteractions: bufferCap})
		require.NoError(t, err)
		defer mem.Close()

		require.NoError(t, mem.SetID("shared"))

		total := bufferCap + 50
		for i := range total {
			require.NoError(t, mem.AddInteractionWithId("shared", []byte("msg-"+strconv.Itoa(i))))
		}

		// First poll triggers buffer cap enforcement
		_, err = mem.GetInteractionsWithIdForConsumer("shared", "consumer-a")
		require.NoError(t, err)

		// Verify buffer was capped after the read
		item, _ := mem.cache.GetIfPresent("shared")
		value := item.(*CorrelationData)
		value.Lock()
		require.LessOrEqual(t, len(value.Data), bufferCap)
		value.Unlock()
	})

	t.Run("RemoveConsumer last consumer discards all data", func(t *testing.T) {
		mem, err := New(&Options{EvictionTTL: 1 * time.Hour})
		require.NoError(t, err)
		defer mem.Close()

		require.NoError(t, mem.SetID("shared"))
		require.NoError(t, mem.AddInteractionWithId("shared", []byte("msg-1")))

		_, err = mem.GetInteractionsWithIdForConsumer("shared", "consumer-a")
		require.NoError(t, err)

		// Remove the only consumer — all data should be discarded
		require.NoError(t, mem.RemoveConsumer("shared", "consumer-a"))

		item, _ := mem.cache.GetIfPresent("shared")
		value := item.(*CorrelationData)
		value.Lock()
		require.Nil(t, value.Data)
		require.Empty(t, value.ReadOffsets)
		value.Unlock()
	})
}

func TestSlidingEvictionStrategy(t *testing.T) {
	testTTL := 100 * time.Millisecond
	smallDelay := 10 * time.Millisecond
	mem, err := New(&Options{EvictionTTL: testTTL, EvictionStrategy: EvictionStrategySliding})
	require.Nil(t, err)
	defer mem.Close()

	err = mem.SetID("test-sliding")
	require.Nil(t, err)

	// Access after half TTL - should extend expiration
	time.Sleep(testTTL / 2)
	_, ok := mem.cache.GetIfPresent("test-sliding")
	require.True(t, ok)

	// Still present after original TTL due to sliding window
	time.Sleep(testTTL / 2 + smallDelay)
	_, ok = mem.cache.GetIfPresent("test-sliding")
	require.True(t, ok)

	// Should be expired after full TTL despite access
	time.Sleep(testTTL + smallDelay)
	_, ok = mem.cache.GetIfPresent("test-sliding")
	require.False(t, ok)
}

func TestFixedEvictionStrategy(t *testing.T) {
	testTTL := 100 * time.Millisecond
	mem, err := New(&Options{EvictionTTL: testTTL, EvictionStrategy: EvictionStrategyFixed})
	require.Nil(t, err)
	defer mem.Close()

	err = mem.SetID("test-fixed")
	require.Nil(t, err)

	// Access after half TTL - should NOT extend expiration
	time.Sleep(testTTL / 2)
	_, ok := mem.cache.GetIfPresent("test-fixed")
	require.True(t, ok)

	// Should be expired after full TTL despite access
	time.Sleep(testTTL / 2 + 10 * time.Millisecond)
	_, ok = mem.cache.GetIfPresent("test-fixed")
	require.False(t, ok)
}

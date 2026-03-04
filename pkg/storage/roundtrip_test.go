package storage

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"testing"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/google/uuid"
	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
)

// interaction mirrors server.Interaction to avoid circular import
type interaction struct {
	Protocol      string              `json:"protocol"`
	UniqueID      string              `json:"unique-id"`
	FullId        string              `json:"full-id"`
	QType         string              `json:"q-type,omitempty"`
	RawRequest    string              `json:"raw-request,omitempty"`
	RawResponse   string              `json:"raw-response,omitempty"`
	SMTPFrom      string              `json:"smtp-from,omitempty"`
	RemoteAddress string              `json:"remote-address"`
	Timestamp     time.Time           `json:"timestamp"`
	AsnInfo       []map[string]string `json:"asninfo,omitempty"`
}

// Realistic DNS message dump (from miekg/dns String() output)
const dnsRequest = `;; opcode: QUERY, status: NOERROR, id: 12345
;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags: ; udp: 4096

;; QUESTION SECTION:
;abc123def456ghi.oast.fun.	IN	 A
`

const dnsResponse = `;; opcode: QUERY, status: NOERROR, id: 12345
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 2, ADDITIONAL: 2

;; QUESTION SECTION:
;abc123def456ghi.oast.fun.	IN	 A

;; ANSWER SECTION:
abc123def456ghi.oast.fun.	3600	IN	A	1.2.3.4

;; AUTHORITY SECTION:
oast.fun.	3600	IN	NS	ns1.oast.fun.
oast.fun.	3600	IN	NS	ns2.oast.fun.

;; ADDITIONAL SECTION:
ns1.oast.fun.	3600	IN	A	1.2.3.4
ns2.oast.fun.	3600	IN	A	1.2.3.4
`

func generateRSAKeyPair(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubBytes})
	return priv, base64.StdEncoding.EncodeToString(pubPem)
}

func clientDecrypt(t *testing.T, priv *rsa.PrivateKey, aesKeyEncrypted string, cipherData string) []byte {
	t.Helper()
	decodedKey, err := base64.StdEncoding.DecodeString(aesKeyEncrypted)
	require.NoError(t, err)
	keyPlaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, decodedKey, nil)
	require.NoError(t, err)
	cipherText, err := base64.StdEncoding.DecodeString(cipherData)
	require.NoError(t, err)
	require.Greater(t, len(cipherText), aes.BlockSize)
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	block, err := aes.NewCipher(keyPlaintext)
	require.NoError(t, err)
	stream := cipher.NewCTR(block, iv)
	decoded := make([]byte, len(cipherText))
	stream.XORKeyStream(decoded, cipherText)
	return decoded
}

func TestFullRoundTripInMemory(t *testing.T) {
	mem, err := New(&Options{EvictionTTL: 1 * time.Hour})
	require.NoError(t, err)
	defer mem.Close()

	priv, pubKeyB64 := generateRSAKeyPair(t)
	secret := uuid.New().String()
	correlationID := xid.New().String()

	err = mem.SetIDPublicKey(correlationID, secret, pubKeyB64)
	require.NoError(t, err)

	// Create and store 3 DNS interactions (like dns_server.go does)
	for i := 0; i < 3; i++ {
		inter := &interaction{
			Protocol:      "dns",
			UniqueID:      "abc123def456ghi",
			FullId:        "abc123def456ghi.oast.fun",
			QType:         "A",
			RawRequest:    dnsRequest,
			RawResponse:   dnsResponse,
			RemoteAddress: "10.0.0.1",
			Timestamp:     time.Now(),
		}
		data, err := jsoniter.Marshal(inter)
		require.NoError(t, err, "encode interaction %d", i)

		err = mem.AddInteraction(correlationID, data)
		require.NoError(t, err, "add interaction %d", i)
	}

	// Retrieve
	data, aesKey, err := mem.GetInteractions(correlationID, secret)
	require.NoError(t, err)
	require.Len(t, data, 3)

	// Decrypt and unmarshal each (like client.go does)
	for i, d := range data {
		plaintext := clientDecrypt(t, priv, aesKey, d)
		result := &interaction{}
		err = jsoniter.Unmarshal(plaintext, result)
		require.NoError(t, err, "unmarshal interaction %d: plaintext=%q", i, string(plaintext[:min(len(plaintext), 100)]))
		require.Equal(t, "dns", result.Protocol)
		require.Equal(t, "abc123def456ghi", result.UniqueID)
		require.Equal(t, dnsRequest, result.RawRequest)
		require.Equal(t, dnsResponse, result.RawResponse)
	}
}

func TestFullRoundTripDisk(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "interactsh-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	db, err := New(&Options{EvictionTTL: 1 * time.Hour, DbPath: tmpDir})
	require.NoError(t, err)
	defer db.Close()

	priv, pubKeyB64 := generateRSAKeyPair(t)
	secret := uuid.New().String()
	correlationID := xid.New().String()

	err = db.SetIDPublicKey(correlationID, secret, pubKeyB64)
	require.NoError(t, err)

	// Create and store 3 DNS interactions
	for i := 0; i < 3; i++ {
		inter := &interaction{
			Protocol:      "dns",
			UniqueID:      "abc123def456ghi",
			FullId:        "abc123def456ghi.oast.fun",
			QType:         "A",
			RawRequest:    dnsRequest,
			RawResponse:   dnsResponse,
			RemoteAddress: "10.0.0.1",
			Timestamp:     time.Now(),
		}
		data, err := jsoniter.Marshal(inter)
		require.NoError(t, err, "encode interaction %d", i)

		err = db.AddInteraction(correlationID, data)
		require.NoError(t, err, "add interaction %d", i)
	}

	// Retrieve
	data, aesKey, err := db.GetInteractions(correlationID, secret)
	require.NoError(t, err)
	require.Len(t, data, 3)

	// Decrypt and unmarshal each
	for i, d := range data {
		plaintext := clientDecrypt(t, priv, aesKey, d)
		result := &interaction{}
		err = jsoniter.Unmarshal(plaintext, result)
		require.NoError(t, err, "unmarshal interaction %d: plaintext=%q", i, string(plaintext[:min(len(plaintext), 100)]))
		require.Equal(t, "dns", result.Protocol)
		require.Equal(t, "abc123def456ghi", result.UniqueID)
		require.Equal(t, dnsRequest, result.RawRequest)
		require.Equal(t, dnsResponse, result.RawResponse)
	}
}

// TestPollResponseRoundTrip tests the full flow including the HTTP PollResponse JSON encoding
func TestPollResponseRoundTrip(t *testing.T) {
	type PollResponse struct {
		Data    []string `json:"data"`
		Extra   []string `json:"extra"`
		AESKey  string   `json:"aes_key"`
		TLDData []string `json:"tlddata,omitempty"`
	}

	mem, err := New(&Options{EvictionTTL: 1 * time.Hour})
	require.NoError(t, err)
	defer mem.Close()

	priv, pubKeyB64 := generateRSAKeyPair(t)
	secret := uuid.New().String()
	correlationID := xid.New().String()

	err = mem.SetIDPublicKey(correlationID, secret, pubKeyB64)
	require.NoError(t, err)

	// Store a DNS interaction
	inter := &interaction{
		Protocol:      "dns",
		UniqueID:      "abc123def456ghi",
		FullId:        "abc123def456ghi.oast.fun",
		QType:         "A",
		RawRequest:    dnsRequest,
		RawResponse:   dnsResponse,
		RemoteAddress: "10.0.0.1",
		Timestamp:     time.Now(),
	}
	interData, err := jsoniter.Marshal(inter)
	require.NoError(t, err)
	err = mem.AddInteraction(correlationID, interData)
	require.NoError(t, err)

	// Retrieve (server side)
	data, aesKey, err := mem.GetInteractions(correlationID, secret)
	require.NoError(t, err)

	// Simulate PollResponse JSON encoding/decoding (server→client HTTP)
	response := &PollResponse{Data: data, AESKey: aesKey}
	var responseBuf bytes.Buffer
	err = jsoniter.NewEncoder(&responseBuf).Encode(response)
	require.NoError(t, err)

	// Decode on client side
	receivedResponse := &PollResponse{}
	err = jsoniter.NewDecoder(&responseBuf).Decode(receivedResponse)
	require.NoError(t, err)

	require.Len(t, receivedResponse.Data, 1)

	// Decrypt and unmarshal
	plaintext := clientDecrypt(t, priv, receivedResponse.AESKey, receivedResponse.Data[0])
	result := &interaction{}
	err = jsoniter.Unmarshal(plaintext, result)
	require.NoError(t, err, "unmarshal failed: plaintext[:100]=%q", string(plaintext[:min(len(plaintext), 100)]))
	require.Equal(t, "dns", result.Protocol)
}

// TestTrailingNewlineHandling verifies that the trailing \n from Encode() doesn't cause issues
func TestTrailingNewlineHandling(t *testing.T) {
	inter := &interaction{
		Protocol:      "dns",
		UniqueID:      "test",
		FullId:        "test.example.com",
		RemoteAddress: "1.2.3.4",
		Timestamp:     time.Now(),
	}
	buffer := &bytes.Buffer{}
	err := jsoniter.NewEncoder(buffer).Encode(inter)
	require.NoError(t, err)

	encoded := buffer.Bytes()
	t.Logf("Encoded JSON length: %d", len(encoded))
	t.Logf("Last byte: 0x%02x (newline=%v)", encoded[len(encoded)-1], encoded[len(encoded)-1] == '\n')

	// Verify trailing newline is present
	require.Equal(t, byte('\n'), encoded[len(encoded)-1], "Encode() should append trailing newline")

	// Verify jsoniter.Unmarshal handles trailing newline
	result := &interaction{}
	err = jsoniter.Unmarshal(encoded, result)
	require.NoError(t, err, "Unmarshal should handle trailing newline")
	require.Equal(t, "dns", result.Protocol)
}

// TestJsoniterControlCharacterEscaping verifies jsoniter properly escapes control characters
func TestJsoniterControlCharacterEscaping(t *testing.T) {
	// DNS message String() output contains tabs and newlines
	inter := &interaction{
		Protocol:      "dns",
		UniqueID:      "test",
		FullId:        "test.example.com",
		RawRequest:    "line1\nline2\ttab\rcarriage",
		RemoteAddress: "1.2.3.4",
		Timestamp:     time.Now(),
	}
	buffer := &bytes.Buffer{}
	err := jsoniter.NewEncoder(buffer).Encode(inter)
	require.NoError(t, err)

	encoded := buffer.Bytes()
	// Check that no raw control characters (except the trailing \n) exist in the JSON
	for i, b := range encoded[:len(encoded)-1] { // skip trailing \n
		if b < 0x20 {
			t.Errorf("Found unescaped control character 0x%02x at position %d in JSON: ...%q...",
				b, i, string(encoded[max(0, i-20):min(len(encoded), i+20)]))
		}
	}

	// Verify round-trip
	result := &interaction{}
	err = jsoniter.Unmarshal(encoded, result)
	require.NoError(t, err)
	require.Equal(t, "line1\nline2\ttab\rcarriage", result.RawRequest)
}

// TestStaleDataCleanupOnReRegistration verifies that stale LevelDB data from a
// previous registration (encrypted with an old AES key) is purged when the same
// correlation ID is re-registered after cache eviction.
func TestStaleDataCleanupOnReRegistration(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "interactsh-stale-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Use a very short eviction TTL so the cache entry gets evicted quickly
	db, err := New(&Options{EvictionTTL: 100 * time.Millisecond, DbPath: tmpDir})
	require.NoError(t, err)
	defer db.Close()

	secret := uuid.New().String()
	correlationID := xid.New().String()

	// First registration
	priv1, pubKey1 := generateRSAKeyPair(t)
	err = db.SetIDPublicKey(correlationID, secret, pubKey1)
	require.NoError(t, err)

	// Store an interaction encrypted with AES key K1
	inter := &interaction{
		Protocol:      "dns",
		UniqueID:      "first-registration",
		FullId:        "first.example.com",
		RemoteAddress: "1.2.3.4",
		Timestamp:     time.Now(),
	}
	data1, err := jsoniter.Marshal(inter)
	require.NoError(t, err)
	err = db.AddInteraction(correlationID, data1)
	require.NoError(t, err)

	// Wait for cache eviction
	time.Sleep(200 * time.Millisecond)

	// Verify cache entry is evicted
	_, found := db.cache.GetIfPresent(correlationID)
	require.False(t, found, "cache entry should be evicted")

	// Re-register with the same correlation ID (simulates session restore)
	// This generates a NEW AES key K2
	priv2, pubKey2 := generateRSAKeyPair(t)
	err = db.SetIDPublicKey(correlationID, secret, pubKey2)
	require.NoError(t, err)

	// Store a new interaction encrypted with K2
	inter2 := &interaction{
		Protocol:      "dns",
		UniqueID:      "second-registration",
		FullId:        "second.example.com",
		RemoteAddress: "5.6.7.8",
		Timestamp:     time.Now(),
	}
	data2, err := jsoniter.Marshal(inter2)
	require.NoError(t, err)
	err = db.AddInteraction(correlationID, data2)
	require.NoError(t, err)

	// Retrieve interactions
	interactions, aesKey, err := db.GetInteractions(correlationID, secret)
	require.NoError(t, err)

	// Should only have 1 interaction (the new one), not the stale one
	require.Len(t, interactions, 1, "stale data from first registration should have been purged")

	// Decrypt and verify it's the second interaction
	plaintext := clientDecrypt(t, priv2, aesKey, interactions[0])
	result := &interaction{}
	err = jsoniter.Unmarshal(plaintext, result)
	require.NoError(t, err, "should unmarshal successfully with new key")
	require.Equal(t, "second-registration", result.UniqueID)

	// priv1 is no longer useful (old key pair)
	_ = priv1
}

// TestCacheEvictionCleansLevelDB verifies the OnCacheRemovalCallback properly
// deletes LevelDB entries when cache entries are evicted.
func TestCacheEvictionCleansLevelDB(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "interactsh-eviction-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	db, err := New(&Options{EvictionTTL: 100 * time.Millisecond, DbPath: tmpDir})
	require.NoError(t, err)
	defer db.Close()

	secret := uuid.New().String()
	correlationID := xid.New().String()

	_, pubKey := generateRSAKeyPair(t)
	err = db.SetIDPublicKey(correlationID, secret, pubKey)
	require.NoError(t, err)

	// Store an interaction
	inter := &interaction{
		Protocol:      "dns",
		UniqueID:      "test",
		FullId:        "test.example.com",
		RemoteAddress: "1.2.3.4",
		Timestamp:     time.Now(),
	}
	data, err := jsoniter.Marshal(inter)
	require.NoError(t, err)
	err = db.AddInteraction(correlationID, data)
	require.NoError(t, err)

	// Verify data exists in LevelDB
	raw, err := db.db.Get([]byte(correlationID), nil)
	require.NoError(t, err)
	require.NotEmpty(t, raw)

	// Wait for cache eviction
	time.Sleep(200 * time.Millisecond)

	// Force cache cleanup (GetIfPresent triggers lazy eviction)
	db.cache.GetIfPresent(correlationID)
	// Small delay for async eviction callback
	time.Sleep(50 * time.Millisecond)

	// LevelDB entry should be cleaned up by OnCacheRemovalCallback
	_, err = db.db.Get([]byte(correlationID), nil)
	require.Error(t, err, "LevelDB entry should be deleted after cache eviction")
}

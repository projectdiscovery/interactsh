package client

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"errors"

	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	asnmap "github.com/projectdiscovery/asnmap/libs"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/interactsh/pkg/options"
	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/interactsh/pkg/settings"
	"github.com/projectdiscovery/interactsh/pkg/storage"
	"github.com/projectdiscovery/retryablehttp-go"
	errorutil "github.com/projectdiscovery/utils/errors"
	iputil "github.com/projectdiscovery/utils/ip"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/rs/xid"
	zbase32 "gopkg.in/corvus-ch/zbase32.v1"
	"gopkg.in/yaml.v3"
)

var authError = errors.New("couldn't authenticate to the server")

type State uint8

const (
	Idle State = iota
	Polling
	Closed
)

// Client is a client for communicating with interactsh server instance.
type Client struct {
	busy                     sync.RWMutex
	State                    atomic.Value
	correlationID            string
	secretKey                string
	serverURL                *url.URL
	httpClient               *retryablehttp.Client
	privKey                  *rsa.PrivateKey
	pubKey                   *rsa.PublicKey
	quitChan                 chan struct{}
	quitKeepAliveChan        chan struct{}
	disableHTTPFallback      bool
	token                    string
	correlationIdLength      int
	CorrelationIdNonceLength int
}

// Options contains configuration options for interactsh client
type Options struct {
	// ServerURL is the URL for the interactsh server.
	ServerURL string
	// Token if the server requires authentication
	Token string
	// DisableHTTPFallback determines if failed requests over https should not be retried over http
	DisableHTTPFallback bool
	// CorrelationIdLength of the preamble
	CorrelationIdLength int
	// CorrelationIdNonceLengthLength of the nonce
	CorrelationIdNonceLength int
	// HTTPClient use a custom http client
	HTTPClient *retryablehttp.Client
	// SessionInfo to resume an existing session
	SessionInfo *options.SessionInfo
	// keepAliveInterval to renew the session
	KeepAliveInterval time.Duration
}

// DefaultOptions is the default options for the interact client
var DefaultOptions = &Options{
	ServerURL:                "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me",
	CorrelationIdLength:      settings.CorrelationIdLengthDefault,
	CorrelationIdNonceLength: settings.CorrelationIdNonceLengthDefault,
}

// New creates a new client instance based on provided options
func New(options *Options) (*Client, error) {
	// if correlation id lengths and nonce are not specified fallback to default:
	if options.CorrelationIdLength == 0 {
		options.CorrelationIdLength = DefaultOptions.CorrelationIdLength
	}
	if options.CorrelationIdNonceLength == 0 {
		options.CorrelationIdNonceLength = DefaultOptions.CorrelationIdNonceLength
	}

	var httpclient *retryablehttp.Client
	if options.HTTPClient != nil {
		httpclient = options.HTTPClient
	} else {
		opts := retryablehttp.DefaultOptionsSpraying
		opts.Timeout = 10 * time.Second
		httpclient = retryablehttp.NewClient(opts)
	}

	// INTERACTSH_TLS_VERIFY enforces TLS (cleartext is a fatal error)
	if os.Getenv("INTERACTSH_TLS_VERIFY") == "true" {
		t, ok := httpclient.HTTPClient.Transport.(*http.Transport)
		if !ok {
			return nil, errors.New("could not get http transport")
		}
		t.TLSClientConfig.InsecureSkipVerify = false
		if stringsutil.HasPrefixI(options.ServerURL, "http://") {
			return nil, errors.New("tls enforced - invalid URL with cleartext http")
		}
		interactshServerURL := options.ServerURL
		if !stringsutil.HasPrefixAnyI(interactshServerURL, "https://") {
			interactshServerURL = fmt.Sprintf("https://%s", interactshServerURL)
		}
		if _, err := httpclient.HTTPClient.Get(interactshServerURL); err != nil {
			return nil, errorutil.NewWithErr(err).Msgf("certificate verification failed")
		}
	}

	var correlationID, secretKey, token string

	if options.SessionInfo != nil {
		correlationID = options.SessionInfo.CorrelationID
		secretKey = options.SessionInfo.SecretKey
		token = options.SessionInfo.Token
	} else {
		// Generate a random ksuid which will be used as server secret.
		correlationID = xid.New().String()
		if len(correlationID) > options.CorrelationIdLength {
			correlationID = correlationID[:options.CorrelationIdLength]
		}
		secretKey = uuid.New().String()
		token = options.Token
	}

	client := &Client{
		secretKey:                secretKey,
		correlationID:            correlationID,
		httpClient:               httpclient,
		token:                    token,
		disableHTTPFallback:      options.DisableHTTPFallback,
		correlationIdLength:      options.CorrelationIdLength,
		CorrelationIdNonceLength: options.CorrelationIdNonceLength,
	}

	if options.SessionInfo != nil {
		privKey, err := x509.ParsePKCS1PrivateKey([]byte(options.SessionInfo.PrivateKey))
		if err == nil {
			client.privKey = privKey
		}
		pubKey, err := decodePublicKey(options.SessionInfo.PublicKey)
		if err != nil {
			return nil, errorutil.NewWithErr(err).Msgf("failed to decode public key")
		}
		client.pubKey = pubKey
		if serverURL, err := url.Parse(options.SessionInfo.ServerURL); err == nil {
			client.serverURL = serverURL
		}
		// attempts to re-register - server will reject is already existing
		registrationRequest, err := encodeRegistrationRequest(options.SessionInfo.PublicKey, options.SessionInfo.SecretKey, options.SessionInfo.CorrelationID)
		if err != nil {
			return nil, err
		}
		// silently fails to re-register if the session is still alive
		_ = client.performRegistration(options.SessionInfo.ServerURL, registrationRequest)
	} else {
		payload, err := client.initializeRSAKeys()
		if err != nil {
			return nil, errorutil.NewWithErr(err).Msgf("could not initialize rsa keys")
		}

		if err := client.parseServerURLs(options.ServerURL, payload); err != nil {
			return nil, errorutil.NewWithErr(err).Msgf("could not register to servers")
		}
	}

	// start a keep alive routine
	client.quitKeepAliveChan = make(chan struct{})
	if options.KeepAliveInterval > 0 {
		ticker := time.NewTicker(options.KeepAliveInterval)
		go func() {
			for {
				// exit if the client is closed
				if client.State.Load() == Closed {
					return
				}
				select {
				case <-ticker.C:
					// todo: internal logic needs a complete redesign
					pubKeyData, err := encodePublicKey(client.pubKey)
					if err != nil {
						return
					}
					// attempts to re-register - server will reject is already existing
					registrationRequest, err := encodeRegistrationRequest(pubKeyData, client.secretKey, client.correlationID)
					if err != nil {
						return
					}
					// silently fails to re-register if the session is still alive
					_ = client.performRegistration(client.serverURL.String(), registrationRequest)
				case <-client.quitKeepAliveChan:
					ticker.Stop()
					return
				}
			}
		}()
	}

	return client, nil
}

// initializeRSAKeys does the one-time initialization for RSA crypto mechanism
// and returns the data payload for the client.
func (c *Client) initializeRSAKeys() ([]byte, error) {
	// Generate a 2048-bit private-key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("could not generate rsa private key")
	}
	c.privKey = priv
	c.pubKey = &priv.PublicKey

	pubKeyData, err := encodePublicKey(c.pubKey)
	if err != nil {
		return nil, err
	}

	return encodeRegistrationRequest(pubKeyData, c.secretKey, c.correlationID)
}

func encodeRegistrationRequest(publicKey, secretkey, correlationID string) ([]byte, error) {
	register := server.RegisterRequest{
		PublicKey:     publicKey,
		SecretKey:     secretkey,
		CorrelationID: correlationID,
	}

	data, err := jsoniter.Marshal(register)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("could not marshal register request")
	}
	return data, nil
}

func encodePublicKey(pubKey *rsa.PublicKey) (string, error) {
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", errorutil.NewWithErr(err).Msgf("could not marshal public key")
	}
	pubkeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubkeyBytes,
	})

	encoded := base64.StdEncoding.EncodeToString(pubkeyPem)
	return encoded, nil
}

func decodePublicKey(data string) (*rsa.PublicKey, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}

	pubkeyPem, _ := pem.Decode(decodedBytes)
	if pubkeyPem == nil {
		return nil, errors.New("failed to decode PEM block containing the public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(pubkeyPem.Bytes)
	if err != nil {
		return nil, err
	}

	if rsaPubKey, ok := pubKey.(*rsa.PublicKey); ok {
		return rsaPubKey, nil
	}

	return nil, errors.New("unsupported public key")
}

// parseServerURLs parses server url string. Multiple URLs are supported
// comma separated and a random one will be used on runtime.
//
// If the https scheme is not working, http is tried. url can be comma separated
// domains or full urls as well.
//
// If the first picked random domain doesn't work, the list of domains is iterated
// after being shuffled.
func (c *Client) parseServerURLs(serverURL string, payload []byte) error {
	if serverURL == "" {
		return errors.New("invalid server url provided")
	}

	values := strings.Split(serverURL, ",")
	registerFunc := func(idx int, value string) error {
		if !stringsutil.HasPrefixAny(value, "http://", "https://") {
			value = fmt.Sprintf("https://%s", value)
		}
		parsed, err := url.Parse(value)
		if err != nil {
			return errorutil.NewWithErr(err).Msgf("could not parse server URL")
		}
	makeReq:
		if err := c.performRegistration(parsed.String(), payload); err != nil {
			if !c.disableHTTPFallback && parsed.Scheme == "https" {
				parsed.Scheme = "http"
				gologger.Verbose().Msgf("Could not register to %s: %s, retrying with http\n", parsed.String(), err)
				goto makeReq
			}
			return err
		}
		c.serverURL = parsed
		return nil
	}

	var registerErrors []error

	sliceutil.VisitRandom(values, func(index int, item string) error {
		if c.serverURL != nil {
			return errors.New("already registered")
		}
		err := registerFunc(index, item)
		if err != nil {
			gologger.Verbose().Msgf("Could not register to %s: %s, retrying with remaining\n", item, err)
			registerErrors = append(registerErrors, err)
		}
		return nil
	})

	if c.serverURL == nil {
		return errors.Join(registerErrors...)
	}

	return nil
}

// InteractionCallback is a callback function for a reported interaction
type InteractionCallback func(*server.Interaction)

// StartPolling the server each duration and returns any events
// that may have been captured by the collaborator server.
func (c *Client) StartPolling(duration time.Duration, callback InteractionCallback) error {
	switch c.State.Load() {
	case Polling:
		return errors.New("client is already polling")
	case Closed:
		return errors.New("client is closed")
	}

	c.State.Store(Polling)

	ticker := time.NewTicker(duration)
	c.quitChan = make(chan struct{})
	go func() {
		for {
			// exit if the client is not polling
			if c.State.Load() != Polling {
				return
			}
			select {
			case <-ticker.C:
				err := c.getInteractions(callback)
				if err != nil {
					if errorutil.IsAny(err, authError) {
						gologger.Error().Msgf("Could not authenticate to the server %v", err)
					} else if errorutil.IsAny(err, storage.ErrCorrelationIdNotFound) {
						gologger.Error().Msgf("The correlation id was not found (probably evicted due to inactivity): %v", err)
					}
				}
			case <-c.quitChan:
				ticker.Stop()
				return
			}
		}
	}()

	return nil
}

// getInteractions returns the interactions from the server.
func (c *Client) getInteractions(callback InteractionCallback) error {
	c.busy.RLock()
	defer c.busy.RUnlock()

	builder := &strings.Builder{}
	builder.WriteString(c.serverURL.String())
	builder.WriteString("/poll?id=")
	builder.WriteString(c.correlationID)
	builder.WriteString("&secret=")
	builder.WriteString(c.secretKey)
	req, err := retryablehttp.NewRequest("GET", builder.String(), nil)
	if err != nil {
		return err
	}

	if c.token != "" {
		req.Header.Add("Authorization", c.token)
	}

	resp, err := c.httpClient.Do(req)
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
		}
	}()
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return authError
		}
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return errorutil.NewWithErr(err).Msgf("could not read response body")
		}
		if stringsutil.ContainsAny(string(data), storage.ErrCorrelationIdNotFound.Error()) {
			return storage.ErrCorrelationIdNotFound
		}
		return fmt.Errorf("could not poll interactions: %s", string(data))
	}
	response := &server.PollResponse{}
	if err := jsoniter.NewDecoder(resp.Body).Decode(response); err != nil {
		gologger.Error().Msgf("Could not decode interactions: %v\n", err)
		return err
	}

	for _, data := range response.Data {
		plaintext, err := c.decryptMessage(response.AESKey, data)
		if err != nil {
			gologger.Error().Msgf("Could not decrypt interaction: %v\n", err)
			continue
		}
		interaction := &server.Interaction{}
		if err := jsoniter.Unmarshal(plaintext, interaction); err != nil {
			gologger.Error().Msgf("Could not unmarshal interaction data interaction: %v\n", err)
			continue
		}
		callback(interaction)
	}

	for _, plaintext := range response.Extra {
		interaction := &server.Interaction{}
		if err := jsoniter.UnmarshalFromString(plaintext, interaction); err != nil {
			gologger.Error().Msgf("Could not unmarshal interaction data interaction: %v\n", err)
			continue
		}
		callback(interaction)
	}

	// handle root-tld data if any
	for _, data := range response.TLDData {
		interaction := &server.Interaction{}
		if err := jsoniter.UnmarshalFromString(data, interaction); err != nil {
			gologger.Error().Msgf("Could not unmarshal interaction data interaction: %v\n", err)
			continue
		}
		callback(interaction)
	}

	return nil
}

// TryGetAsnInfo attempts to enrich interaction with asn data
func (c *Client) TryGetAsnInfo(interaction *server.Interaction) error {
	var remoteIp string
	if iputil.IsIP(interaction.RemoteAddress) {
		remoteIp = interaction.RemoteAddress
	} else {
		var err error
		remoteIp, _, err = net.SplitHostPort(interaction.RemoteAddress)
		if err != nil {
			return err
		}
	}

	if asnItems, err := asnmap.DefaultClient.GetData(remoteIp); err == nil && len(asnItems) > 0 {
		for _, asnItem := range asnItems {
			// convert to map to prune and turn fields into camel case
			newOutputAsnItem := make(map[string]string)
			newOutputAsnItem["first-ip"] = asnItem.FirstIp
			newOutputAsnItem["last-ip"] = asnItem.LastIp
			newOutputAsnItem["asn"] = fmt.Sprintf("AS%d", asnItem.ASN)
			newOutputAsnItem["country"] = asnItem.Country
			newOutputAsnItem["org"] = asnItem.Org
			interaction.AsnInfo = append(interaction.AsnInfo, newOutputAsnItem)
		}
	}
	return nil
}

// StopPolling the interactsh server.
func (c *Client) StopPolling() error {
	c.busy.Lock()
	defer c.busy.Unlock()

	if c.State.Load() != Polling {
		return errors.New("client is not polling")
	}
	close(c.quitChan)

	c.State.Store(Idle)

	return nil
}

// Close closes the collaborator client and deregisters from the
// collaborator server if not explicitly asked by the user.
func (c *Client) Close() error {
	c.busy.Lock()
	defer c.busy.Unlock()

	if c.State.Load() == Polling {
		return errors.New("client should stop polling before closing")
	}
	if c.State.Load() == Closed {
		return errors.New("client is already closed")
	}

	close(c.quitKeepAliveChan)

	register := server.DeregisterRequest{
		CorrelationID: c.correlationID,
		SecretKey:     c.secretKey,
	}
	data, err := jsoniter.Marshal(register)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("could not marshal deregister request")
	}
	URL := c.serverURL.String() + "/deregister"
	req, err := retryablehttp.NewRequest("POST", URL, bytes.NewReader(data))
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("could not create new request")
	}
	req.ContentLength = int64(len(data))

	if c.token != "" {
		req.Header.Add("Authorization", c.token)
	}

	resp, err := c.httpClient.Do(req)
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
		}
	}()
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("could not make deregister request")
	}
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("could not deregister to server: %s", string(data))
	}

	c.State.Store(Closed)

	return nil
}

// performRegistration registers the current client with the master server using the
// provided RSA Public Key as well as Correlation Key.
func (c *Client) performRegistration(serverURL string, payload []byte) error {
	// By default we attempt registration once before switching to the next server
	ctx := context.WithValue(context.Background(), retryablehttp.RETRY_MAX, 0)

	URL := serverURL + "/register"
	req, err := retryablehttp.NewRequestWithContext(ctx, "POST", URL, bytes.NewReader(payload))
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("could not create new request")
	}
	req.ContentLength = int64(len(payload))

	if c.token != "" {
		req.Header.Add("Authorization", c.token)
	}

	resp, err := c.httpClient.Do(req)
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
		}
	}()
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("could not make register request")
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return errors.New("invalid token provided for interactsh server")
	}
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("could not register to server: %s", string(data))
	}
	response := make(map[string]interface{})
	if err := jsoniter.NewDecoder(resp.Body).Decode(&response); err != nil {
		return errorutil.NewWithErr(err).Msgf("could not register to server")
	}
	message, ok := response["message"]
	if !ok {
		return errors.New("could not get register response")
	}
	if message.(string) != "registration successful" {
		return fmt.Errorf("could not get register response: %s", message.(string))
	}

	c.State.Store(Idle)

	return nil
}

// URL returns a new URL that can be used for external interaction requests.
func (c *Client) URL() string {
	if c.State.Load() == Closed {
		return ""
	}
	data := make([]byte, c.CorrelationIdNonceLength)
	_, _ = rand.Read(data)
	randomData := zbase32.StdEncoding.EncodeToString(data)
	if len(randomData) > c.CorrelationIdNonceLength {
		randomData = randomData[:c.CorrelationIdNonceLength]
	}

	builder := &strings.Builder{}
	builder.Grow(len(c.correlationID) + len(randomData) + len(c.serverURL.Host) + 1)
	builder.WriteString(c.correlationID)
	builder.WriteString(randomData)
	builder.WriteString(".")
	builder.WriteString(c.serverURL.Host)
	URL := builder.String()
	return URL
}

// decryptMessage decrypts an AES-256-RSA-OAEP encrypted message to string
func (c *Client) decryptMessage(key string, secureMessage string) ([]byte, error) {
	decodedKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}

	// Decrypt the key plaintext first
	keyPlaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, c.privKey, decodedKey, nil)
	if err != nil {
		return nil, err
	}

	cipherText, err := base64.StdEncoding.DecodeString(secureMessage)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(keyPlaintext)
	if err != nil {
		return nil, err
	}

	if len(cipherText) < aes.BlockSize {
		return nil, errors.New("ciphertext block size is too small")
	}

	// IV is at the start of the Ciphertext
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	// XORKeyStream can work in-place if the two arguments are the same.
	stream := cipher.NewCFBDecrypter(block, iv)
	decoded := make([]byte, len(cipherText))
	stream.XORKeyStream(decoded, cipherText)
	return decoded, nil
}

func (c *Client) SaveSessionTo(filename string) error {
	privateKeyData := x509.MarshalPKCS1PrivateKey(c.privKey)
	publicKeyData, err := encodePublicKey(c.pubKey)
	if err != nil {
		return err
	}
	sessionInfo := &options.SessionInfo{
		ServerURL:     c.serverURL.String(),
		Token:         c.token,
		PrivateKey:    string(privateKeyData),
		CorrelationID: c.correlationID,
		SecretKey:     c.secretKey,
		PublicKey:     publicKeyData,
	}
	data, err := yaml.Marshal(sessionInfo)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, os.ModePerm)
}

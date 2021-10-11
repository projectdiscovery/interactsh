// Package acme implements an automatically renewing
// acme wildcard certificate generation implementation
// that performs rolling updates on the http.Server.
//
// It uses interactsh built-in DNS server for DNS challenges.
package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/eggsampler/acme/v3"
	"github.com/jasonlvhit/gocron"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/fileutil"
)

// TXTUpdateCallback is called when a TXT value is to be updated
type TXTUpdateCallback func(value string)

// Generate generates new certificates based on provided info
func Generate(certFile, keyFile, email, domains string, txtCallback TXTUpdateCallback) error {
	httpclient, dialer, err := getHTTPClient()
	if err != nil {
		return err
	}
	defer dialer.Close()

	client, err := acme.NewClient(acme.LetsEncryptProduction, acme.WithHTTPClient(httpclient))
	if err != nil {
		return errors.Wrap(err, "could not create acme client")
	}
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("error creating private key: %v", err)
	}
	account, err := client.NewAccount(privKey, false, true, []string{"mailto:" + email}...)
	if err != nil {
		return fmt.Errorf("error creating new account: %v", err)
	}

	// collect the comma separated domains into acme identifiers
	domainList := strings.Split(domains, ",")
	var ids []acme.Identifier
	for _, domain := range domainList {
		ids = append(ids, acme.Identifier{Type: "dns", Value: domain})
	}

	// create a new order with the acme service given the provided identifiers
	log.Printf("Creating new order for domains: %s\n", domainList)
	order, err := client.NewOrder(account, ids)
	if err != nil {
		return errors.Wrap(err, "could not create new order")
	}
	log.Printf("Order created: %s\n", order.URL)

	// loop through each of the provided authorization urls
	for _, authUrl := range order.Authorizations {
		// fetch the authorization data from the acme service given the provided authorization url
		log.Printf("Fetching authorization: %s\n", authUrl)
		auth, err := client.FetchAuthorization(account, authUrl)
		if err != nil {
			return errors.Wrap(err, "error fetching authorization url")
		}
		log.Printf("Fetched authorization: %s\n", auth.Identifier.Value)

		// grab a dns-01 challenge from the authorization if it exists
		chal, ok := auth.ChallengeMap[acme.ChallengeTypeDNS01]
		if !ok {
			return errors.New("no dns challenge in auth")
		}

		txt := acme.EncodeDNS01KeyAuthorization(chal.KeyAuthorization)
		txtCallback(txt) // this will set value for DNS server
		time.Sleep(10 * time.Second)

		// update the acme server that the challenge file is ready to be queried
		log.Printf("Updating challenge for authorization %s: %s\n", auth.Identifier.Value, chal.URL)
		chal, err = client.UpdateChallenge(account, chal)
		if err != nil {
			return fmt.Errorf("error updating authorization %s challenge: %v", auth.Identifier.Value, err)
		}
		log.Printf("Challenge updated\n")
	}

	// create a csr for the new certificate
	log.Printf("Generating certificate private key\n")
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errors.Wrap(err, "could not generate cert key")
	}

	b := key2pem(certKey)

	// write the key to the key file as a pem encoded key
	log.Printf("Writing key file: %s\n", keyFile)
	if err := ioutil.WriteFile(keyFile, b, 0600); err != nil {
		return errors.Wrap(err, "could not write key file")
	}

	// create the new csr template
	tpl := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          certKey.Public(),
		Subject:            pkix.Name{CommonName: domainList[0]},
		DNSNames:           domainList,
	}
	csrDer, err := x509.CreateCertificateRequest(rand.Reader, tpl, certKey)
	if err != nil {
		return errors.Wrap(err, "could not create cert request")
	}
	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		return errors.Wrap(err, "could not parse cert request")
	}

	// finalize the order with the acme server given a csr
	log.Printf("Finalising order: %s\n", order.URL)
	order, err = client.FinalizeOrder(account, order, csr)
	if err != nil {
		return errors.Wrap(err, "could not finalize order")
	}

	// fetch the certificate chain from the finalized order provided by the acme server
	log.Printf("Fetching certificate: %s\n", order.Certificate)
	certs, err := client.FetchCertificates(account, order.Certificate)
	if err != nil {
		return errors.Wrap(err, "could not fetch order request")
	}

	// write the pem encoded certificate chain to file
	log.Printf("Saving certificate to: %s\n", certFile)
	var pemData []string
	for _, c := range certs {
		pemData = append(pemData, strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		}))))
	}
	if err := ioutil.WriteFile(certFile, []byte(strings.Join(pemData, "\n")), 0600); err != nil {
		return errors.Wrap(err, "could not write cert file")
	}
	return nil
}

func key2pem(certKey *ecdsa.PrivateKey) []byte {
	certKeyEnc, _ := x509.MarshalECPrivateKey(certKey)

	return pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: certKeyEnc,
	})
}

// AutoTLS is a client for daily update checked ACME TLS
type AutoTLS struct {
	certMu   sync.RWMutex
	cert     *tls.Certificate
	certPath string
	keyPath  string
}

type CertRefreshFunc func(email, domains string, txtCallback TXTUpdateCallback) error

// NewAutomaticTLS returns a new auto-tls ACME DNS based client
func NewAutomaticTLS(email, domains string, txtCallback TXTUpdateCallback) (*AutoTLS, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, errors.Wrap(err, "could not get home directory")
	}
	config := path.Join(home, ".config", "interactsh")
	_ = os.MkdirAll(config, 0777)

	certFile := path.Join(config, "cert.crt")
	keyFile := path.Join(config, "cert.key")

	result := &AutoTLS{
		certPath: certFile,
		keyPath:  keyFile,
	}
	certNotExists := !fileutil.FileExists(certFile) || !fileutil.FileExists(keyFile)
	if certNotExists {
		if err := Generate(certFile, keyFile, email, domains, txtCallback); err != nil {
			return nil, errors.Wrap(err, "could not generate new certs")
		}
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	result.cert = &cert

	acmeUpdateFunc := func() {
		timeNow := time.Now()
		toExpire := false

		cert, _ := result.GetCertificateFunc()(nil)
		for _, cert := range cert.Certificate {
			parsed, err := x509.ParseCertificate(cert)
			if err == nil && parsed != nil {
				// Since the cert is going to expire, mark it as such.
				if timeNow.AddDate(0, 0, 30).After(parsed.NotAfter) {
					toExpire = true
				}
			}
		}
		if toExpire {
			if err := Generate(certFile, keyFile, email, domains, txtCallback); err != nil {
				log.Printf("Could not check for ACME TLS updates: %s\n", err)
			}
			log.Printf("Received Update, reloading TLS certificate and key from %q and %q\n", certFile, keyFile)
			if err := result.maybeReload(); err != nil {
				log.Printf("Keeping old TLS certificate because the new one could not be loaded: %v\n", err)
			}
		} else {
			log.Printf("TLS certificates are not expiring, continue!\n")
		}
	}
	if !certNotExists {
		acmeUpdateFunc() // Run at once on startup and then run in gocron
	}
	_ = gocron.Every(1).Day().Do(acmeUpdateFunc)
	return result, nil
}

func (kpr *AutoTLS) maybeReload() error {
	newCert, err := tls.LoadX509KeyPair(kpr.certPath, kpr.keyPath)
	if err != nil {
		return err
	}
	kpr.certMu.Lock()
	defer kpr.certMu.Unlock()
	kpr.cert = &newCert
	return nil
}

func (kpr *AutoTLS) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		kpr.certMu.RLock()
		defer kpr.certMu.RUnlock()
		return kpr.cert, nil
	}
}

func getFastDialer() (*fastdialer.Dialer, error) {
	fastdialerOpts := fastdialer.DefaultOptions
	fastdialerOpts.EnableFallback = true
	fastdialerOpts.WithDialerHistory = false
	fastdialerOpts.CacheType = fastdialer.Memory
	fastdialerOpts.WithCleanup = false
	return fastdialer.NewDialer(fastdialerOpts)
}

func getHTTPClient() (*http.Client, *fastdialer.Dialer, error) {
	dialer, err := getFastDialer()
	if err != nil {
		return nil, nil, err
	}
	transport := &http.Transport{
		DialContext:         dialer.Dial,
		MaxIdleConnsPerHost: -1,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: true,
	}

	client := &http.Client{Transport: transport}
	return client, dialer, nil
}

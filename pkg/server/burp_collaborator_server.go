package server

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/asaskevich/govalidator"
	jsoniter "github.com/json-iterator/go"
	"github.com/miekg/dns"
	"github.com/projectdiscovery/gologger"
)

var clientPartRegex = regexp.MustCompile("^1g(notused|([0-9a-f]+y[0-9a-f]+y))z$")

// BurpResponse is the response for a burp polling request
type BurpResponse struct {
	Responses []*BurpItem `json:"responses,omitempty"`
}

type BurpItem struct {
	Protocol          string      `json:"protocol"`
	OpCode            string      `json:"opCode"`
	InteractionString string      `json:"interactionString"`
	ClientPart        string      `json:"clientPart"`
	Data              interface{} `json:"data"`
	Time              string      `json:"time"`
	Client            string      `json:"client"`
	ClientPort        string      `json:"clientPort"`
}

type BurpHTTPData struct {
	Request  string `json:"request"`
	Response string `json:"response"`
}

type BurpDNSData struct {
	Subdomain  string `json:"subDomain"`
	Type       uint16 `json:"type"`
	RawRequest string `json:"rawRequest"`
}

type BurpSMTPData struct {
	Sender       string   `json:"sender"`
	Recipients   []string `json:"recipients"`
	Message      string   `json:"message"`
	Conversation string   `json:"conversation"`
}

// generate burp collaborator id
func biidGenBurpID(biid string) (string, error) {
	pw, err := base64.StdEncoding.DecodeString(biid)
	hash := sha1.New()
	hash.Write(pw)
	ID := base36Encode(hash.Sum(nil))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%c%s%c", ID[0:10], base36Hash(ID[0:10]), ID[10:20], base36Hash(ID[10:20])), nil
}

// convert interaction data to burp response
func convert2BurpItem(data string) (*BurpItem, error) {
	interaction := &Interaction{}
	if err := jsoniter.UnmarshalFromString(data, interaction); err != nil {
		return nil, err
	}
	item := &BurpItem{
		Protocol:          interaction.Protocol,
		OpCode:            "1", // idk
		InteractionString: interaction.UniqueID,
		ClientPart:        getBurpClientPart(interaction.UniqueID),
		Client:            interaction.RemoteAddress,
		ClientPort:        "0",
		Time:              fmt.Sprintf("%d", interaction.Timestamp.UnixMilli()),
	}
	switch interaction.Protocol {
	case "dns":
		item.Data = &BurpDNSData{
			Subdomain:  interaction.FullId,
			Type:       dns.StringToType[interaction.QType],
			RawRequest: base64.StdEncoding.EncodeToString([]byte(interaction.RawRequest)),
		}
	case "http", "https":
		item.Data = &BurpHTTPData{
			Request:  base64.StdEncoding.EncodeToString([]byte(interaction.RawRequest)),
			Response: base64.StdEncoding.EncodeToString([]byte(interaction.RawResponse)),
		}
	case "smtp", "smtps":
		item.Data = &BurpSMTPData{
			Sender:       base64.StdEncoding.EncodeToString([]byte(interaction.SMTPFrom)),
			Recipients:   []string{base64.StdEncoding.EncodeToString([]byte(interaction.UniqueID))},
			Message:      base64.StdEncoding.EncodeToString([]byte(interaction.RawRequest)),
			Conversation: base64.StdEncoding.EncodeToString([]byte(interaction.RawRequest)),
		}
	default:
		return nil, fmt.Errorf("no support")
	}
	return item, nil
}

// burpHandler is a handler for burp poll results
func (h *HTTPServer) burpHandler(w http.ResponseWriter, req *http.Request) {
	biid := req.URL.Query().Get("biid")
	if biid == "test" { // health check
		w.Write([]byte("{}"))
		return
	}
	if biid == "" {
		jsonError(w, "no biid specified for poll", http.StatusBadRequest)
		return
	}
	ID, err := biidGenBurpID(biid)
	if err != nil {
		jsonError(w, "wrong biid for poll", http.StatusBadRequest)
		return
	}

	data, err := h.options.Storage.GetInteractionsWithId(ID)

	if err != nil {
		h.options.Storage.RemoveID(ID, "")
		h.options.Storage.SetID(ID)
	}
	if len(data) == 0 {
		w.Write([]byte("{}"))
		return
	}
	response := BurpResponse{
		Responses: []*BurpItem{},
	}
	for _, s := range data {
		item, err := convert2BurpItem(s)
		if err != nil {
			gologger.Warning().Msgf("Could not convert interactions for %s: %s\n", ID, err)
			continue
		}
		response.Responses = append(response.Responses, item)
	}
	if err := jsoniter.NewEncoder(w).Encode(response); err != nil {
		gologger.Warning().Msgf("Could not encode interactions for %s: %s\n", ID, err)
		jsonError(w, fmt.Sprintf("could not encode interactions: %s", err), http.StatusBadRequest)
		return
	}
	gologger.Debug().Msgf("Polled %d interactions for %s correlationID\n", len(data), ID)
}

// just like burp response
func (h *HTTPServer) burpMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Server", "Burp Collaborator https://burpcollaborator.net/")
		w.Header().Set("X-Collaborator-Version", "4")
		w.Header().Set("X-Collaborator-Time", fmt.Sprintf("%d", time.Now().UnixMilli()))
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, req)
	})
}

func (options *Options) getBurpCorrelationID(s string) string {
	if govalidator.IsAlphanumeric(s) && len(s) >= 32 {
		iv, c1 := s[0:2], s[2]
		if base36Hash(iv) != c1 {
			return ""
		}
		decode := base36XorDecode(iv, s[3:])
		if !govalidator.IsAlphanumeric(decode) {
			return ""
		}
		ID, c2, c3, clientPart := decode[0:22], decode[10], decode[21], decode[22:]
		if base36Hash(ID[0:10]) == c2 && base36Hash(ID[11:21]) == c3 && clientPartRegex.MatchString(clientPart) {
			return ID
		}
	}
	return ""
}

func (options *Options) getCorrelationID(uniqueID string) string {
	burpID := options.getBurpCorrelationID(uniqueID)
	if burpID != "" {
		return burpID
	}
	return uniqueID[:options.CorrelationIdLength]
}

func getBurpClientPart(s string) string {
	decode := base36XorDecode(s[0:2], s[3:])
	return decode[24 : len(decode)-1]
}

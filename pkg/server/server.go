package server

// Interaction is an interaction recieved to the server.
type Interaction struct {
	// Protocol for interaction, can contains HTTP/DNS/SMTP,etc.
	Protocol string `json:"protocol"`
	// UniqueID is the uniqueID for the subdomain recieving the interaction.
	UniqueID string `json:"unique-id"`
}

// RegisterRequest is a request for client registration to interactsh server.
type RegisterRequest struct {
	// PublicKey is the public RSA Key of the client.
	PublicKey []byte `json:"public-key"`
	// CorrelationID is an ID for correlation with requests.
	CorrelationID string `json:"correlation-id"`
}

// RegisterHandler is a handler for client register requests
func RegisterHandler() {

}

// DeregisterRequest is a request for client deregistration to interactsh server.
type DeregisterRequest struct {
	// CorrelationID is an ID for correlation with requests.
	CorrelationID string `json:"correlation-id"`
}

// DeregisterHandler is a handler for client deregister requests
func DeregisterHandler() {

}

// PollRequest is a request for client polling for interactions
type PollRequest struct {
	// CorrelationID is an ID for correlation with requests.
	CorrelationID string `json:"correlation-id"`
}

// PollResponse is the response for a polling request
type PollResponse struct {
	Data [][]byte `json:"data"`
}

// PollHandler is a handler for client poll requests
func PollHandler() {

}

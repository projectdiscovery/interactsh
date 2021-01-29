package server

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

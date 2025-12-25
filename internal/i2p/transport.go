package i2p

import (
	"context"
	"net"
)

// Transport defines the interface for I2P connectivity
// This abstraction allows swapping between different I2P implementations:
// - HTTP bridge (current Java I2P via i2ptunnel)
// - SAM bridge (Java I2P SAM protocol)
// - Native go-i2p (future when streaming library matures)
type Transport interface {
	// Start initializes the transport layer
	Start(ctx context.Context) error

	// Stop gracefully shuts down the transport
	Stop(ctx context.Context) error

	// GetDestination returns this service's .b32.i2p address
	GetDestination() string

	// GetClientDestination extracts client's I2P destination from context or connection
	GetClientDestination(ctx context.Context) string

	// Listen creates a server accepting I2P connections (for native implementations)
	Listen() (net.Listener, error)

	// Dial connects to an I2P destination (for outbound connections)
	Dial(destination string) (net.Conn, error)
}

// TransportMode indicates which transport implementation to use
type TransportMode string

const (
	// TransportHTTPBridge uses Java I2P's HTTP tunnel (current implementation)
	TransportHTTPBridge TransportMode = "http_bridge"

	// TransportSAM uses Java I2P's SAM protocol
	TransportSAM TransportMode = "sam"

	// TransportNative uses go-i2p library (future)
	TransportNative TransportMode = "native"
)

// Config holds transport configuration
type Config struct {
	Mode TransportMode

	// HTTP Bridge settings (current)
	// No special config needed - relies on i2ptunnel forwarding X-I2P-* headers

	// SAM settings (future)
	SAMAddress string

	// Native go-i2p settings (future)
	// Will be added when go-i2p streaming is ready
}

// ContextKey type for context values
type ContextKey string

const (
	// ContextKeyDestB32 is the context key for I2P destination
	ContextKeyDestB32 ContextKey = "i2p_dest_b32"
)

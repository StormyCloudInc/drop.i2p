package i2p

import (
	"context"
	"errors"
	"net"
	"net/http"
)

// HTTPBridgeTransport implements Transport for current HTTP-over-I2P approach
// This works with Java I2P's i2ptunnel which sets X-I2P-* headers
type HTTPBridgeTransport struct {
	destination string // Our .b32.i2p address (if known)
}

// NewHTTPBridgeTransport creates a new HTTP bridge transport
func NewHTTPBridgeTransport() *HTTPBridgeTransport {
	return &HTTPBridgeTransport{}
}

// Start initializes the transport (no-op for HTTP bridge)
func (t *HTTPBridgeTransport) Start(ctx context.Context) error {
	return nil
}

// Stop shuts down the transport (no-op for HTTP bridge)
func (t *HTTPBridgeTransport) Stop(ctx context.Context) error {
	return nil
}

// GetDestination returns our I2P destination
func (t *HTTPBridgeTransport) GetDestination() string {
	return t.destination
}

// SetDestination sets our I2P destination (for configuration)
func (t *HTTPBridgeTransport) SetDestination(dest string) {
	t.destination = dest
}

// GetClientDestination extracts client's I2P destination from context
func (t *HTTPBridgeTransport) GetClientDestination(ctx context.Context) string {
	if dest := ctx.Value(ContextKeyDestB32); dest != nil {
		if d, ok := dest.(string); ok {
			return d
		}
	}
	return ""
}

// Listen is not supported for HTTP bridge (i2ptunnel handles this)
func (t *HTTPBridgeTransport) Listen() (net.Listener, error) {
	return nil, errors.New("Listen not supported for HTTP bridge transport")
}

// Dial is not supported for HTTP bridge (use standard HTTP client)
func (t *HTTPBridgeTransport) Dial(destination string) (net.Conn, error) {
	return nil, errors.New("Dial not supported for HTTP bridge transport")
}

// ExtractI2PHeaders extracts I2P headers from HTTP request and returns context
// This should be used by middleware to add I2P info to request context
func ExtractI2PHeaders(r *http.Request) context.Context {
	ctx := r.Context()

	// Try different header formats that i2ptunnel might set
	destB32 := r.Header.Get("X-I2P-DestB32")
	if destB32 == "" {
		destB32 = r.Header.Get("X-I2P-DestHash")
	}
	if destB32 == "" {
		// Some setups use base64 destination
		destB64 := r.Header.Get("X-I2P-DestB64")
		if destB64 != "" {
			// For now, just store the base64; could convert to b32 later
			destB32 = destB64
		}
	}

	if destB32 != "" {
		ctx = context.WithValue(ctx, ContextKeyDestB32, destB32)
	}

	return ctx
}

// I2PMiddleware is HTTP middleware that extracts I2P headers into context
func I2PMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := ExtractI2PHeaders(r)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetDestinationFromRequest extracts I2P destination directly from request
// Convenience function for handlers that need destination
func GetDestinationFromRequest(r *http.Request) string {
	// First check context (if middleware ran)
	if dest := r.Context().Value(ContextKeyDestB32); dest != nil {
		if d, ok := dest.(string); ok {
			return d
		}
	}

	// Fallback to headers
	destB32 := r.Header.Get("X-I2P-DestB32")
	if destB32 == "" {
		destB32 = r.Header.Get("X-I2P-DestHash")
	}
	return destB32
}

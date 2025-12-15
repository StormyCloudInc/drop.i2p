package i2p

import (
	"context"
	"errors"
	"net"
)

// NativeTransport is a stub implementation for future go-i2p integration
// When go-i2p's streaming library is ready, this will be implemented
// See: https://github.com/go-i2p/go-i2p
type NativeTransport struct {
	config Config
	// Future: router *goi2p.Router
}

// NewNativeTransport creates a new native go-i2p transport (stub)
func NewNativeTransport(cfg Config) *NativeTransport {
	return &NativeTransport{
		config: cfg,
	}
}

// Start initializes the go-i2p router
func (t *NativeTransport) Start(ctx context.Context) error {
	// TODO: When go-i2p streaming is ready:
	// 1. Initialize the router
	// 2. Create tunnel destination
	// 3. Start accepting connections
	return errors.New("native go-i2p transport not yet implemented - waiting for streaming library")
}

// Stop shuts down the go-i2p router
func (t *NativeTransport) Stop(ctx context.Context) error {
	// TODO: Graceful shutdown of router
	return nil
}

// GetDestination returns our I2P destination
func (t *NativeTransport) GetDestination() string {
	// TODO: Return destination from router
	return ""
}

// GetClientDestination extracts client's I2P destination from context
func (t *NativeTransport) GetClientDestination(ctx context.Context) string {
	// With native transport, this would come from the connection itself
	if dest := ctx.Value(ContextKeyDestB32); dest != nil {
		if d, ok := dest.(string); ok {
			return d
		}
	}
	return ""
}

// Listen creates a server accepting I2P connections
func (t *NativeTransport) Listen() (net.Listener, error) {
	// TODO: Create tunnel and return listener
	return nil, errors.New("native go-i2p transport not yet implemented")
}

// Dial connects to an I2P destination
func (t *NativeTransport) Dial(destination string) (net.Conn, error) {
	// TODO: Create outbound stream to destination
	return nil, errors.New("native go-i2p transport not yet implemented")
}

/*
Future implementation notes for go-i2p integration:

1. go-i2p 0.1.0 has core router functionality but streaming is incomplete
2. When streaming is ready, the implementation would look like:

   func (t *NativeTransport) Start(ctx context.Context) error {
       // Initialize router
       router, err := goi2p.NewRouter(goi2p.RouterConfig{
           // Config options
       })
       if err != nil {
           return err
       }
       t.router = router

       // Create destination
       dest, err := router.CreateDestination()
       if err != nil {
           return err
       }
       t.destination = dest

       return router.Start(ctx)
   }

3. Benefits of native go-i2p:
   - No Java I2P router dependency
   - Direct control over tunnels
   - Multi-destination support for bonded transfers
   - Lower latency (no HTTP overhead)

4. For now, use HTTPBridgeTransport which works with existing Java I2P setup
*/

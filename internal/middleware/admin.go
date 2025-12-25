package middleware

import (
	"crypto/subtle"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// AdminConfig holds admin authentication configuration
type AdminConfig struct {
	PasswordHash string // bcrypt hash of admin password
	Username     string // Admin username (default: "admin")
}

// AdminAuth creates middleware for admin authentication using Basic Auth
func AdminAuth(config AdminConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If no password hash configured, deny access
			if config.PasswordHash == "" {
				http.Error(w, "Admin access not configured", http.StatusForbidden)
				return
			}

			username, password, ok := r.BasicAuth()
			if !ok {
				w.Header().Set("WWW-Authenticate", `Basic realm="Admin Area"`)
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}

			// Check username
			expectedUsername := config.Username
			if expectedUsername == "" {
				expectedUsername = "admin"
			}

			if subtle.ConstantTimeCompare([]byte(username), []byte(expectedUsername)) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="Admin Area"`)
				http.Error(w, "Invalid credentials", http.StatusUnauthorized)
				return
			}

			// Check password against bcrypt hash
			if err := bcrypt.CompareHashAndPassword([]byte(config.PasswordHash), []byte(password)); err != nil {
				w.Header().Set("WWW-Authenticate", `Basic realm="Admin Area"`)
				http.Error(w, "Invalid credentials", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// HashPassword generates a bcrypt hash for a password
// Useful for generating the initial admin password hash
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

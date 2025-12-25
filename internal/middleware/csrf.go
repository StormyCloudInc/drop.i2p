package middleware

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
)

// csrfContextKey is the context key for storing the CSRF token
type csrfContextKey struct{}

// CSRFConfig holds configuration for CSRF protection
type CSRFConfig struct {
	TokenLength int
	CookieName  string
	MaxAge      int // seconds
}

// DefaultCSRFConfig returns default CSRF configuration
func DefaultCSRFConfig() CSRFConfig {
	return CSRFConfig{
		TokenLength: 32,
		CookieName:  "csrf_token",
		MaxAge:      3600, // 1 hour
	}
}

// generateToken creates a cryptographically secure random token
func generateToken(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback - should never happen
		return ""
	}
	return hex.EncodeToString(bytes)
}

// CSRF creates middleware for CSRF protection
// Works without JavaScript - uses double-submit cookie pattern
func CSRF(config CSRFConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// For GET/HEAD/OPTIONS requests, ensure a CSRF token cookie exists
			if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
				var token string
				// Check if token cookie already exists
				if cookie, err := r.Cookie(config.CookieName); err == nil {
					token = cookie.Value
				} else {
					// Generate new token and set cookie
					token = generateToken(config.TokenLength)
					if token != "" {
						http.SetCookie(w, &http.Cookie{
							Name:     config.CookieName,
							Value:    token,
							Path:     "/",
							MaxAge:   config.MaxAge,
							HttpOnly: false, // Must be readable by forms
							SameSite: http.SameSiteStrictMode,
						})
					}
				}
				// Store token in context for handlers to access
				ctx := context.WithValue(r.Context(), csrfContextKey{}, token)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// For POST/PUT/DELETE requests, validate CSRF token
			// Skip validation for API endpoints (they use different auth)
			if isAPIEndpoint(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// Get token from cookie
			cookie, err := r.Cookie(config.CookieName)
			if err != nil {
				http.Error(w, "CSRF token missing", http.StatusForbidden)
				return
			}

			// Get token from form
			formToken := r.FormValue("csrf_token")
			if formToken == "" {
				// Also check header for AJAX requests (if ever needed)
				formToken = r.Header.Get("X-CSRF-Token")
			}

			if formToken == "" {
				http.Error(w, "CSRF token not provided", http.StatusForbidden)
				return
			}

			// Constant-time comparison to prevent timing attacks
			if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(formToken)) != 1 {
				http.Error(w, "CSRF token mismatch", http.StatusForbidden)
				return
			}

			// Token is valid - generate a new one for the next request (token rotation)
			newToken := generateToken(config.TokenLength)
			if newToken != "" {
				http.SetCookie(w, &http.Cookie{
					Name:     config.CookieName,
					Value:    newToken,
					Path:     "/",
					MaxAge:   config.MaxAge,
					HttpOnly: false,
					SameSite: http.SameSiteStrictMode,
				})
			}

			next.ServeHTTP(w, r)
		})
	}
}

// isAPIEndpoint checks if the request is to an API endpoint
// API endpoints use different authentication (API keys) and don't need CSRF
func isAPIEndpoint(path string) bool {
	return len(path) >= 4 && path[:4] == "/api"
}

// GetCSRFToken retrieves the CSRF token from the request context
// Used by handlers to pass token to templates
func GetCSRFToken(r *http.Request) string {
	if token, ok := r.Context().Value(csrfContextKey{}).(string); ok {
		return token
	}
	// Fallback to cookie if not in context (shouldn't happen normally)
	cookie, err := r.Cookie("csrf_token")
	if err != nil {
		return ""
	}
	return cookie.Value
}

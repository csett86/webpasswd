package main

import (
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// templateData is the data passed to the HTML template on each render.
type templateData struct {
	Success bool
	Message string
	// Preserve the username field so the user does not have to retype it.
	Username string
}

var indexTmpl *template.Template

func main() {
	addr := flag.String("addr", ":8080", "TCP address to listen on")
	rateLimit := flag.Int("rate-limit", 5, "maximum password-change attempts per IP per window")
	rateWindow := flag.Duration("rate-window", 15*time.Minute, "sliding window duration for rate limiting")
	trustXFF := flag.Bool("x-forwarded-for", false, "trust the X-Forwarded-For / X-Real-IP headers (set when behind a reverse proxy)")
	flag.Parse()

	// Parse the embedded template at startup so we catch errors early.
	var err error
	indexTmpl, err = template.ParseFiles("templates/index.html")
	if err != nil {
		log.Fatalf("failed to parse template: %v", err)
	}

	rl := NewRateLimiter(*rateLimit, *rateWindow)

	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	mux.HandleFunc("/", makeHandler(rl, *trustXFF))

	srv := &http.Server{
		Addr:         *addr,
		Handler:      securityHeaders(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	logger := log.New(os.Stderr, "", log.LstdFlags)
	logger.Printf("webpasswd listening on %s", *addr)
	if err := srv.ListenAndServe(); err != nil {
		logger.Fatalf("server error: %v", err)
	}
}

// securityHeaders wraps a handler and sets conservative security headers.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// makeHandler returns the HTTP handler for GET / and POST /.
func makeHandler(rl *RateLimiter, trustXFF bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		switch r.Method {
		case http.MethodGet:
			renderForm(w, templateData{})
		case http.MethodPost:
			handlePost(w, r, rl, trustXFF)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// handlePost processes the password-change form submission.
func handlePost(w http.ResponseWriter, r *http.Request, rl *RateLimiter, trustXFF bool) {
	ip := clientIP(r, trustXFF)

	// Rate-limit check before touching PAM.
	if !rl.Allow(ip) {
		retryAfter := rl.RetryAfter(ip)
		w.Header().Set("Retry-After", fmt.Sprintf("%.0f", retryAfter.Seconds()))
		w.WriteHeader(http.StatusTooManyRequests)
		renderForm(w, templateData{
			Message: fmt.Sprintf("Too many attempts. Please try again in %s.", retryAfter.Round(time.Second)),
		})
		log.Printf("rate-limited ip=%s", ip)
		return
	}

	if err := r.ParseForm(); err != nil {
		renderError(w, "Invalid form submission.")
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	newPasswordConfirm := r.FormValue("new_password_confirm")

	// Preserve username for re-render.
	data := templateData{Username: username}

	// Validate inputs.
	if username == "" || currentPassword == "" || newPassword == "" || newPasswordConfirm == "" {
		data.Message = "All fields are required."
		renderForm(w, data)
		return
	}
	if newPassword != newPasswordConfirm {
		data.Message = "New passwords do not match."
		renderForm(w, data)
		return
	}

	// Attempt the PAM password change.
	err := changePasswordFunc(username, currentPassword, newPassword)
	if err != nil {
		outcome := "error"
		switch {
		case errors.Is(err, ErrAuthFailed):
			data.Message = "Current password is incorrect."
			outcome = "auth_failed"
		case errors.Is(err, ErrPermDenied):
			data.Message = "Password change not allowed. The new password may not satisfy complexity requirements."
			outcome = "perm_denied"
		default:
			data.Message = "Password change failed. Please try again later."
			outcome = "unknown_error"
		}
		log.Printf("password change failed ip=%s username=%s outcome=%s err=%v", ip, username, outcome, err)
		renderForm(w, data)
		return
	}

	log.Printf("password changed successfully ip=%s username=%s", ip, username)
	renderForm(w, templateData{
		Success:  true,
		Message:  "Password changed successfully.",
		Username: username,
	})
}

// renderForm renders the index template with the given data.
func renderForm(w http.ResponseWriter, data templateData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := indexTmpl.Execute(w, data); err != nil {
		log.Printf("template execution error: %v", err)
	}
}

// renderError writes a plain-text error response. Used only for unrecoverable
// pre-template errors.
func renderError(w http.ResponseWriter, msg string) {
	http.Error(w, msg, http.StatusBadRequest)
}

// clientIP extracts the real client IP from the request. When trustXFF is
// true, it honours X-Real-IP and X-Forwarded-For headers (set by a reverse
// proxy). Otherwise it uses the remote address directly.
func clientIP(r *http.Request, trustXFF bool) string {
	if trustXFF {
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			if ip := net.ParseIP(strings.TrimSpace(xri)); ip != nil {
				return ip.String()
			}
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// X-Forwarded-For may be a comma-separated list; the leftmost is the client.
			parts := strings.Split(xff, ",")
			if ip := net.ParseIP(strings.TrimSpace(parts[0])); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

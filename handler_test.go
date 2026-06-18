package main

import (
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func init() {
	// Load the template for handler tests.
	var err error
	indexTmpl, err = template.ParseFiles("templates/index.html")
	if err != nil {
		panic("failed to parse template: " + err.Error())
	}
	// Default to a no-op success for handler tests.
	changePasswordFunc = func(_, _, _ string) error { return nil }
}

// postForm is a helper that submits a POST / request and returns the recorder.
func postForm(t *testing.T, rl *RateLimiter, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	body := values.Encode()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.0.2.1:1234"

	rr := httptest.NewRecorder()
	makeHandler(rl, false)(rr, req)
	return rr
}

func goodForm() url.Values {
	return url.Values{
		"username":             {"alice"},
		"current_password":     {"oldpass1"},
		"new_password":         {"newpass12"},
		"new_password_confirm": {"newpass12"},
	}
}

func TestHandler_GET(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	rr := httptest.NewRecorder()
	rl := NewRateLimiter(5, 15*time.Minute)
	makeHandler(rl, false)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "<form") {
		t.Fatal("expected form in response body")
	}
}

func TestHandler_MissingFields(t *testing.T) {
	rl := NewRateLimiter(5, 15*time.Minute)

	cases := []url.Values{
		{"username": {""}, "current_password": {"x"}, "new_password": {"y"}, "new_password_confirm": {"y"}},
		{"username": {"u"}, "current_password": {""}, "new_password": {"y"}, "new_password_confirm": {"y"}},
		{"username": {"u"}, "current_password": {"x"}, "new_password": {""}, "new_password_confirm": {"y"}},
		{"username": {"u"}, "current_password": {"x"}, "new_password": {"y"}, "new_password_confirm": {""}},
	}

	for _, v := range cases {
		rr := postForm(t, rl, v)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 for missing-field case, got %d", rr.Code)
		}
		body := rr.Body.String()
		if !strings.Contains(body, "All fields are required") {
			t.Errorf("expected 'All fields are required' in response, got:\n%s", body)
		}
	}
}

func TestHandler_PasswordMismatch(t *testing.T) {
	rl := NewRateLimiter(5, 15*time.Minute)
	v := goodForm()
	v.Set("new_password_confirm", "different99")
	rr := postForm(t, rl, v)

	if !strings.Contains(rr.Body.String(), "do not match") {
		t.Fatalf("expected password mismatch message, body: %s", rr.Body.String())
	}
}

func TestHandler_PasswordTooShort(t *testing.T) {
	rl := NewRateLimiter(5, 15*time.Minute)
	v := goodForm()
	v.Set("new_password", "short")
	v.Set("new_password_confirm", "short")
	rr := postForm(t, rl, v)

	if !strings.Contains(rr.Body.String(), "8 characters") {
		t.Fatalf("expected length message, body: %s", rr.Body.String())
	}
}

func TestHandler_AuthFailed(t *testing.T) {
	rl := NewRateLimiter(5, 15*time.Minute)
	changePasswordFunc = func(_, _, _ string) error { return ErrAuthFailed }
	t.Cleanup(func() { changePasswordFunc = func(_, _, _ string) error { return nil } })

	rr := postForm(t, rl, goodForm())
	if !strings.Contains(rr.Body.String(), "incorrect") {
		t.Fatalf("expected auth-failed message, body: %s", rr.Body.String())
	}
}

func TestHandler_PermDenied(t *testing.T) {
	rl := NewRateLimiter(5, 15*time.Minute)
	changePasswordFunc = func(_, _, _ string) error { return ErrPermDenied }
	t.Cleanup(func() { changePasswordFunc = func(_, _, _ string) error { return nil } })

	rr := postForm(t, rl, goodForm())
	if !strings.Contains(rr.Body.String(), "not allowed") {
		t.Fatalf("expected perm-denied message, body: %s", rr.Body.String())
	}
}

func TestHandler_UnknownError(t *testing.T) {
	rl := NewRateLimiter(5, 15*time.Minute)
	changePasswordFunc = func(_, _, _ string) error { return errors.New("some pam error") }
	t.Cleanup(func() { changePasswordFunc = func(_, _, _ string) error { return nil } })

	rr := postForm(t, rl, goodForm())
	if !strings.Contains(rr.Body.String(), "failed") {
		t.Fatalf("expected generic error message, body: %s", rr.Body.String())
	}
}

func TestHandler_Success(t *testing.T) {
	rl := NewRateLimiter(5, 15*time.Minute)
	rr := postForm(t, rl, goodForm())

	if !strings.Contains(rr.Body.String(), "successfully") {
		t.Fatalf("expected success message, body: %s", rr.Body.String())
	}
}

func TestHandler_RateLimit(t *testing.T) {
	now := time.Now()
	rl := newTestRateLimiter(2, time.Minute, func() time.Time { return now })

	// Two allowed attempts.
	for i := 0; i < 2; i++ {
		v := goodForm()
		body := v.Encode()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "192.0.2.1:1234"
		rr := httptest.NewRecorder()
		makeHandler(rl, false)(rr, req)
	}

	// Third attempt must be blocked.
	v := goodForm()
	body := v.Encode()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.0.2.1:1234"
	rr := httptest.NewRecorder()
	makeHandler(rl, false)(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr.Code)
	}
}

func TestClientIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:5432"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	ip := clientIP(req, false)
	if ip != "10.0.0.1" {
		t.Fatalf("expected 10.0.0.1, got %s", ip)
	}
}

func TestClientIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:5432"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.1")

	ip := clientIP(req, true)
	if ip != "1.2.3.4" {
		t.Fatalf("expected 1.2.3.4, got %s", ip)
	}
}

func TestClientIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:5432"
	req.Header.Set("X-Real-IP", "5.6.7.8")

	ip := clientIP(req, true)
	if ip != "5.6.7.8" {
		t.Fatalf("expected 5.6.7.8, got %s", ip)
	}
}

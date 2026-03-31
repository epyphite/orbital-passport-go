package passport

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireAuth_NoCookie(t *testing.T) {
	passport := NewPassportClient("http://passport.test")

	handler := RequireAuth(passport, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called without auth")
	}))

	req := httptest.NewRequest("GET", "/api/wallet", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}

	var body map[string]string
	json.NewDecoder(rr.Body).Decode(&body)
	if body["login_url"] == "" {
		t.Error("expected login_url in response")
	}
}

func TestRequireAuth_ValidSession(t *testing.T) {
	// Mock Passport whoami
	passportSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(cookieName)
		if err != nil || cookie.Value != "valid-session" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(User{
			ID:    "user-123",
			Email: "test@epiphyte.dev",
		})
	}))
	defer passportSrv.Close()

	passport := NewPassportClient(passportSrv.URL)

	var gotUser *User
	handler := RequireAuth(passport, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/wallet", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: "valid-session"})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if gotUser == nil || gotUser.ID != "user-123" {
		t.Error("expected user in context")
	}
}

func TestRequireAuth_InvalidSession(t *testing.T) {
	passportSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer passportSrv.Close()

	passport := NewPassportClient(passportSrv.URL)

	handler := RequireAuth(passport, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called with invalid session")
	}))

	req := httptest.NewRequest("GET", "/api/wallet", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: "expired-session"})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

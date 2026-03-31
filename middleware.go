package passport

import (
	"context"
	"encoding/json"
	"net/http"
)

type contextKey string

const userContextKey contextKey = "user"

// RequireAuth is middleware that validates the passport_session cookie.
// On failure, returns 401 with a login URL for the frontend to redirect.
func RequireAuth(passport *PassportClient, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(cookieName)
		if err != nil || cookie.Value == "" {
			writeUnauthorized(w, passport, r)
			return
		}

		user, err := passport.ValidateSession(r.Context(), cookie.Value)
		if err != nil {
			writeUnauthorized(w, passport, r)
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// UserFromContext extracts the authenticated user from the request context.
func UserFromContext(ctx context.Context) *User {
	user, _ := ctx.Value(userContextKey).(*User)
	return user
}

func writeUnauthorized(w http.ResponseWriter, passport *PassportClient, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)

	returnTo := r.Header.Get("Origin")
	if returnTo == "" {
		returnTo = "https://orbitalshopper.ai"
	}

	json.NewEncoder(w).Encode(map[string]string{
		"error":     "unauthorized",
		"login_url": passport.LoginURL(returnTo),
	})
}

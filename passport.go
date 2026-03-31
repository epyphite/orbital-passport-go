package passport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// User represents an authenticated OrbitalPassport user.
// Maps to the GET /v1/auth/whoami response.
type User struct {
	ID          string `json:"user_id"`
	Email       string `json:"email"`
	Name        *Name  `json:"name"`
	AccountType string `json:"account_type"`
	IsAdmin     bool   `json:"is_admin"`
	KYCLevel    int    `json:"kyc_level"`
	CurrentOrg  string `json:"current_org_id"`
	Roles       []string            `json:"roles"`
	AllOrgRoles map[string][]string `json:"all_org_roles"`
}

// Name holds the user's first and last name.
type Name struct {
	First string `json:"first"`
	Last  string `json:"last"`
}

// HasRole checks if the user has a specific role in a given organization.
func (u *User) HasRole(orgID, role string) bool {
	roles, ok := u.AllOrgRoles[orgID]
	if !ok {
		return false
	}
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

// CodeUser represents user info returned by the exchange code validation.
// Maps to the POST /v1/auth/validate-code response.
type CodeUser struct {
	Valid               bool              `json:"valid"`
	UserID              string            `json:"user_id"`
	Email               string            `json:"email"`
	Name                map[string]string `json:"name"`
	AccountType         string            `json:"account_type"`
	IsAdmin             bool              `json:"is_admin"`
	KYCLevel            int               `json:"kyc_level"`
	DefaultOrganization string            `json:"default_organization"`
	Error               string            `json:"error,omitempty"`
}

// PassportClient validates sessions against OrbitalPassport.
type PassportClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewPassportClient creates a client for session-based auth (cookie validation).
func NewPassportClient(baseURL string) *PassportClient {
	return &PassportClient{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// NewPassportClientWithKey creates a client with a service API key for
// server-to-server calls (validate-code, validate-token).
func NewPassportClientWithKey(baseURL, apiKey string) *PassportClient {
	return &PassportClient{
		baseURL:    baseURL,
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

const cookieName = "passport_session"

// ValidateSession checks the passport_session cookie against Passport's whoami endpoint.
// Returns the authenticated user or an error.
func (p *PassportClient) ValidateSession(ctx context.Context, cookieValue string) (*User, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+"/v1/auth/whoami", nil)
	if err != nil {
		return nil, err
	}
	req.AddCookie(&http.Cookie{Name: cookieName, Value: cookieValue})

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("passport request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("passport returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("decode passport response: %w", err)
	}

	return &user, nil
}

// ValidateCode exchanges a one-time cross-domain SSO code for user info.
// Used when a user logs in on Passport (different domain) and is redirected
// back with ?code=xxx. The code is single-use and expires after 60 seconds.
// Requires a service API key (use NewPassportClientWithKey).
func (p *PassportClient) ValidateCode(ctx context.Context, code string) (*CodeUser, error) {
	if p.apiKey == "" {
		return nil, fmt.Errorf("API key required — use NewPassportClientWithKey")
	}

	body, err := json.Marshal(map[string]string{"code": code})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/v1/auth/validate-code", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", p.apiKey)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("passport request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, ErrUnauthorized
		}
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("passport returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result CodeUser
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode passport response: %w", err)
	}

	if !result.Valid {
		return nil, fmt.Errorf("code validation failed: %s", result.Error)
	}

	return &result, nil
}

// LoginURL returns the Passport login URL with a return_to parameter.
func (p *PassportClient) LoginURL(returnTo string) string {
	return p.baseURL + "/login?return_to=" + url.QueryEscape(returnTo)
}

var ErrUnauthorized = fmt.Errorf("unauthorized")

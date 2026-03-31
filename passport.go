package passport

import (
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

// PassportClient validates sessions against OrbitalPassport.
type PassportClient struct {
	baseURL    string
	httpClient *http.Client
}

func NewPassportClient(baseURL string) *PassportClient {
	return &PassportClient{
		baseURL:    baseURL,
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

// LoginURL returns the Passport login URL with a return_to parameter.
func (p *PassportClient) LoginURL(returnTo string) string {
	return p.baseURL + "/login?return_to=" + url.QueryEscape(returnTo)
}

var ErrUnauthorized = fmt.Errorf("unauthorized")

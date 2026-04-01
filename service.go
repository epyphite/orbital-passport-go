package passport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// DeviceIdentity represents a validated device from POST /v1/devices/validate.
type DeviceIdentity struct {
	Valid          bool   `json:"valid"`
	DeviceID       string `json:"device_id"`
	OrganizationID string `json:"organization_id"`
	ServiceID      string `json:"service_id"`
	DeviceName     string `json:"device_name"`
	DeviceType     string `json:"device_type"`
	Status         string `json:"status"`
	Error          string `json:"error,omitempty"`
}

// TokenResult represents the response from POST /v1/auth/validate-token.
type TokenResult struct {
	Valid              bool                   `json:"valid"`
	TokenType          string                 `json:"token_type"`
	Error              string                 `json:"error,omitempty"`
	Status             string                 `json:"status,omitempty"`
	User               map[string]interface{} `json:"user,omitempty"`
	ExpiresAt          string                 `json:"expires_at,omitempty"`
	OrganizationID     string                 `json:"organization_id,omitempty"`
	DeviceID           string                 `json:"device_id,omitempty"`
	SessionID          string                 `json:"session_id,omitempty"`
	AuthorizedBy       string                 `json:"authorized_by,omitempty"`
	Scope              map[string]interface{} `json:"scope,omitempty"`
	ProvenanceKYCLevel int                    `json:"provenance_kyc_level,omitempty"`
	DelegationDepth    int                    `json:"delegation_depth,omitempty"`
	ApplicationID      string                 `json:"application_id,omitempty"`
	AllowedServices    []string               `json:"allowed_services,omitempty"`
	RateLimit          map[string]int         `json:"rate_limit,omitempty"`
}

// Device represents a device returned from Passport.
type Device struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	DeviceType     string `json:"device_type"`
	OrganizationID string `json:"organization_id"`
	ServiceID      string `json:"service_id"`
	Status         string `json:"status"`
	Token          string `json:"token,omitempty"` // only on creation
	CreatedAt      string `json:"created_at,omitempty"`
}

// CreateDeviceRequest is the body for POST /v1/service/devices.
type CreateDeviceRequest struct {
	UserID         string `json:"user_id"`
	OrganizationID string `json:"organization_id"`
	Name           string `json:"name"`
	DeviceType     string `json:"device_type"`
}

// CreateApprovalRequest is the body for POST /v1/auth/approvals.
type CreateApprovalRequest struct {
	UserID       string                 `json:"user_id"`
	OrgID        string                 `json:"org_id"`
	ApprovalType string                 `json:"approval_type"`
	Payload      map[string]interface{} `json:"payload"`
	CallbackURL  string                 `json:"callback_url,omitempty"`
}

// ApprovalResult is the response from POST /v1/auth/approvals.
type ApprovalResult struct {
	ApprovalID string `json:"approval_id"`
	UserID     string `json:"user_id"`
	ExpiresAt  string `json:"expires_at"`
	PushesSent int    `json:"pushes_sent"`
}

// CreateOrganizationRequest is the body for POST /v1/service/organizations.
type CreateOrganizationRequest struct {
	UserID       string `json:"user_id"`
	Name         string `json:"name"`
	SetAsDefault bool   `json:"set_as_default"`
}

// OrganizationResult is the response from POST /v1/service/organizations.
type OrganizationResult struct {
	Success          bool   `json:"success"`
	OrganizationID   string `json:"organization_id"`
	OrganizationName string `json:"organization_name"`
	Code             string `json:"code,omitempty"`
	UserRole         string `json:"user_role,omitempty"`
}

// ----------------------------------------------------------------------------
// Device Token Validation
// ----------------------------------------------------------------------------

// ValidateDeviceToken validates an opd_ device token.
// Requires a service API key (use NewPassportClientWithKey).
func (p *PassportClient) ValidateDeviceToken(ctx context.Context, token string) (*DeviceIdentity, error) {
	return doServicePost[DeviceIdentity](p, ctx, "/v1/devices/validate", map[string]string{
		"token": token,
	}, "X-Device-Token", token)
}

// ----------------------------------------------------------------------------
// Token Validation (opm_, ops_, opj_, opa_)
// ----------------------------------------------------------------------------

// ValidateToken validates any Passport token (opm_, ops_, opj_, opa_).
// Requires a service API key.
func (p *PassportClient) ValidateToken(ctx context.Context, token string) (*TokenResult, error) {
	result, err := doServicePost[TokenResult](p, ctx, "/v1/auth/validate-token", map[string]string{
		"token": token,
	}, "", "")
	if err != nil {
		return nil, err
	}
	if !result.Valid {
		return result, fmt.Errorf("token invalid: %s", result.Error)
	}
	return result, nil
}

// ----------------------------------------------------------------------------
// Device Management (osk_ service key operations)
// ----------------------------------------------------------------------------

// CreateDevice creates a device token for the service's scope.
func (p *PassportClient) CreateDevice(ctx context.Context, req CreateDeviceRequest) (*Device, error) {
	return doServicePost[Device](p, ctx, "/v1/service/devices", req, "", "")
}

// ListDevices lists devices for a user in an organization.
func (p *PassportClient) ListDevices(ctx context.Context, orgID string) ([]Device, error) {
	if p.apiKey == "" {
		return nil, fmt.Errorf("API key required")
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		p.apiURL+"/v1/organizations/"+orgID+"/devices", nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("X-Service-Key", p.apiKey)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("passport request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("passport returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Devices []Device `json:"devices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return result.Devices, nil
}

// SuspendDevice suspends a device.
func (p *PassportClient) SuspendDevice(ctx context.Context, deviceID string) error {
	return doServiceAction(p, ctx, http.MethodPost, "/v1/devices/"+deviceID+"/suspend")
}

// UnsuspendDevice reactivates a suspended device.
func (p *PassportClient) UnsuspendDevice(ctx context.Context, deviceID string) error {
	return doServiceAction(p, ctx, http.MethodPost, "/v1/devices/"+deviceID+"/reactivate")
}

// RevokeDevice permanently revokes a device.
func (p *PassportClient) RevokeDevice(ctx context.Context, deviceID string) error {
	return doServiceAction(p, ctx, http.MethodDelete, "/v1/devices/"+deviceID)
}

// ----------------------------------------------------------------------------
// Approvals
// ----------------------------------------------------------------------------

// CreateApproval creates an approval request and sends push notification.
func (p *PassportClient) CreateApproval(ctx context.Context, req CreateApprovalRequest) (*ApprovalResult, error) {
	return doServicePost[ApprovalResult](p, ctx, "/v1/auth/approvals", req, "", "")
}

// ----------------------------------------------------------------------------
// Organization Management
// ----------------------------------------------------------------------------

// CreateOrganization creates an organization for a user.
func (p *PassportClient) CreateOrganization(ctx context.Context, req CreateOrganizationRequest) (*OrganizationResult, error) {
	return doServicePost[OrganizationResult](p, ctx, "/v1/service/organizations", req, "", "")
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// doServicePost makes a POST to a service endpoint with API key auth.
func doServicePost[T any](p *PassportClient, ctx context.Context, path string, body interface{}, extraHeader, extraValue string) (*T, error) {
	if p.apiKey == "" {
		return nil, fmt.Errorf("API key required — use NewPassportClientWithKey")
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.apiURL+path, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Service-Key", p.apiKey)
	if extraHeader != "" {
		req.Header.Set(extraHeader, extraValue)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("passport request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrUnauthorized
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("passport returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result T
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &result, nil
}

// doServiceAction makes a POST/DELETE to a service endpoint expecting a simple response.
func doServiceAction(p *PassportClient, ctx context.Context, method, path string) error {
	if p.apiKey == "" {
		return fmt.Errorf("API key required — use NewPassportClientWithKey")
	}

	req, err := http.NewRequestWithContext(ctx, method, p.apiURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Service-Key", p.apiKey)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("passport request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return ErrUnauthorized
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("passport returned HTTP %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

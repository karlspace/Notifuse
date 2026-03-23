# OAuth OIDC Server-Level SSO - Feasibility Evaluation

**Date:** 2026-01-24
**Project:** Notifuse3
**Scope:** SSO at server/instance level for enterprise self-hosted deployments

---

## Executive Summary

**Verdict: FEASIBLE**

For enterprise self-hosted deployments (one instance per company), server-level SSO is the correct architecture. Configuration is stored in the global `settings` table, and all users authenticate through the company's single Identity Provider.

---

## 1. Architecture Decision

### Why Server-Level (Not Workspace-Level)

| Factor | Decision |
|--------|----------|
| Deployment model | One instance per company |
| SSO configuration | Once per instance |
| Identity Provider | Single IdP per company |
| Admin responsibility | IT department configures SSO |
| Workspaces | Internal teams, not separate orgs |

### Storage Location

```
Global settings table (existing)
├── sso_enabled: true
├── sso_config: { OIDC/SAML configuration }
└── sso_enforce: true (disable password login)
```

---

## 2. Current Infrastructure

### Global Settings Table

From `internal/database/schema/system_tables.go`:

```sql
CREATE TABLE settings (
    key VARCHAR(255) PRIMARY KEY,
    value TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
)
```

Currently stores: `version`, `installation_id`, `setup_completed`

**Perfect for SSO config** - just add new keys.

---

## 3. Proposed Data Model

### SSO Configuration

```go
// internal/domain/sso.go

type SSOSettings struct {
    Enabled        bool            `json:"enabled"`
    EnforceSSO     bool            `json:"enforce_sso"`      // Disable password login entirely
    Provider       string          `json:"provider"`         // oidc, saml
    OIDC           *OIDCConfig     `json:"oidc,omitempty"`
    SAML           *SAMLConfig     `json:"saml,omitempty"`   // Future

    // User provisioning
    AutoProvision  bool            `json:"auto_provision"`
    AllowedDomains []string        `json:"allowed_domains,omitempty"`
    DefaultRole    string          `json:"default_role"`     // owner, member

    // Invitation requirement
    RequireInvitation bool         `json:"require_invitation"`

    UpdatedAt      time.Time       `json:"updated_at"`
}

type OIDCConfig struct {
    ClientID              string   `json:"client_id"`
    EncryptedClientSecret string   `json:"encrypted_client_secret,omitempty"`
    DiscoveryURL          string   `json:"discovery_url"`

    // Manual endpoints (if no discovery)
    AuthorizationURL      string   `json:"authorization_url,omitempty"`
    TokenURL              string   `json:"token_url,omitempty"`
    UserInfoURL           string   `json:"user_info_url,omitempty"`
    JwksURL               string   `json:"jwks_url,omitempty"`

    Scopes                []string `json:"scopes"`

    // Claim mappings
    EmailClaim            string   `json:"email_claim,omitempty"`
    NameClaim             string   `json:"name_claim,omitempty"`

    // Runtime only
    ClientSecret          string   `json:"-"`
}
```

### Storage in Settings Table

```sql
-- Key: "sso_config"
-- Value: JSON string of SSOSettings (encrypted sensitive fields)
```

---

## 4. Authentication Flow

```
┌─────────────────────────────────────────────────────────────────┐
│              Server-Level SSO Authentication Flow               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. User visits login page                                      │
│     └─ Frontend checks: GET /api/auth.ssoConfig                 │
│        └─ Returns: { enabled: true, provider: "oidc" }          │
│                                                                  │
│  2. Login page shows:                                           │
│     ├─ "Login with SSO" button (if SSO enabled)                 │
│     └─ Email/password form (if enforce_sso = false)             │
│                                                                  │
│  3. User clicks "Login with SSO"                                │
│     └─ Redirect to: GET /api/auth.sso.authorize                 │
│                                                                  │
│  4. Server builds authorization URL                             │
│     ├─ Load SSO config from settings                            │
│     ├─ Generate state (random + expiry)                         │
│     ├─ Build redirect URL with scopes                           │
│     └─ Redirect to IdP                                          │
│                                                                  │
│  5. User authenticates with company IdP                         │
│                                                                  │
│  6. IdP redirects to: /api/auth.sso.callback?code=xxx&state=yyy │
│                                                                  │
│  7. Server handles callback                                     │
│     ├─ Validate state                                           │
│     ├─ Exchange code for tokens                                 │
│     ├─ Validate ID token signature (via JWKS)                   │
│     ├─ Extract claims (email, name)                             │
│     ├─ Check allowed_domains (if configured)                    │
│     └─ Check invitation requirement                             │
│                                                                  │
│  8. User provisioning                                           │
│     ├─ Find existing user by email                              │
│     ├─ OR create new user (if auto_provision = true)            │
│     ├─ OR reject (if require_invitation and no invitation)      │
│     └─ Create session                                           │
│                                                                  │
│  9. Redirect to dashboard with JWT token                        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. Provisioning Modes

### Mode: Open (auto_provision = true, require_invitation = false)

- Any user with valid SSO + matching domain can join
- Gets added to default workspace with default_role
- Good for: "All employees can access"

### Mode: Invitation Required (require_invitation = true)

- User must have pending invitation
- SSO validates identity, invitation grants access
- Good for: Controlled access, specific team members only

### Mode: Pre-existing Only (auto_provision = false)

- User must already exist in system
- SSO only authenticates, doesn't create users
- Good for: Admin manually creates accounts

### Integration with Existing Invitations

```go
func (s *AuthService) handleSSOCallback(ctx context.Context, code, state string) (*Session, error) {
    // ... validate and extract claims ...

    email := claims.Email

    // Check if user exists
    user, err := s.userRepo.GetByEmail(ctx, email)

    if user == nil {
        // User doesn't exist
        if !ssoConfig.AutoProvision {
            return nil, errors.New("user not found, contact administrator")
        }

        if ssoConfig.RequireInvitation {
            // Check for any pending invitation for this email
            invitation, err := s.invitationRepo.GetByEmail(ctx, email)
            if invitation == nil {
                return nil, errors.New("invitation required to join")
            }

            // Create user and accept invitation
            user = s.createUserFromSSO(claims)
            s.acceptInvitation(invitation, user)
        } else {
            // Auto-provision without invitation
            user = s.createUserFromSSO(claims)
            s.addToDefaultWorkspace(user, ssoConfig.DefaultRole)
        }
    }

    return s.createSession(user)
}
```

---

## 6. API Endpoints

### Public (No Auth Required)

```http
# Get SSO configuration (public, for login page)
GET /api/auth.ssoConfig

Response:
{
  "enabled": true,
  "provider": "oidc",
  "enforce_sso": false,
  "button_text": "Login with Company SSO"  // Optional customization
}
```

```http
# Initiate SSO login
GET /api/auth.sso.authorize
→ Redirects to IdP
```

```http
# SSO callback (from IdP)
GET /api/auth.sso.callback?code=xxx&state=yyy
→ Processes login, redirects to app with token
```

### Admin Only (Requires Auth + Admin Role)

```http
# Configure SSO
POST /api/admin.sso.configure
Authorization: Bearer <admin-token>

{
  "enabled": true,
  "enforce_sso": false,
  "provider": "oidc",
  "oidc": {
    "client_id": "abc123",
    "client_secret": "secret",
    "discovery_url": "https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration",
    "scopes": ["openid", "email", "profile"]
  },
  "auto_provision": true,
  "require_invitation": true,
  "allowed_domains": ["company.com"],
  "default_role": "member"
}
```

```http
# Get SSO configuration (full, for admin)
GET /api/admin.sso.config
Authorization: Bearer <admin-token>

Response:
{
  "enabled": true,
  "provider": "oidc",
  "oidc": {
    "client_id": "abc123",
    "client_secret_set": true,
    "discovery_url": "https://..."
  },
  ...
}
```

```http
# Test SSO configuration
POST /api/admin.sso.test
Authorization: Bearer <admin-token>

Response:
{
  "success": true,
  "provider_name": "Microsoft Azure AD",
  "issuer": "https://login.microsoftonline.com/..."
}
```

```http
# Disable SSO
DELETE /api/admin.sso.config
Authorization: Bearer <admin-token>
```

---

## 7. Provider Compatibility

### OIDC Providers (Supported)

| Provider | Discovery URL |
|----------|---------------|
| Azure AD | `https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration` |
| Google Workspace | `https://accounts.google.com/.well-known/openid-configuration` |
| Okta | `https://{domain}.okta.com/.well-known/openid-configuration` |
| Auth0 | `https://{tenant}.auth0.com/.well-known/openid-configuration` |
| OneLogin | `https://{domain}.onelogin.com/oidc/2/.well-known/openid-configuration` |
| Keycloak | `https://{host}/realms/{realm}/.well-known/openid-configuration` |
| Any OIDC | User provides discovery URL |

### SAML Providers (Future Enhancement)

For enterprises using SAML-only IdPs (some ADFS, PingFederate configs), SAML support would be a future addition using `crewjam/saml` library.

---

## 8. Security Implementation

### Secrets Management

```go
func (c *OIDCConfig) BeforeSave(secretKey []byte) error {
    if c.ClientSecret != "" {
        encrypted, err := crypto.Encrypt([]byte(c.ClientSecret), secretKey)
        if err != nil {
            return err
        }
        c.EncryptedClientSecret = base64.StdEncoding.EncodeToString(encrypted)
        c.ClientSecret = ""
    }
    return nil
}
```

### State Parameter

```go
type SSOState struct {
    Nonce     string    `json:"n"`
    ExpiresAt time.Time `json:"e"`
}

func generateState() (string, error) {
    state := SSOState{
        Nonce:     crypto.RandomString(32),
        ExpiresAt: time.Now().Add(10 * time.Minute),
    }
    // Encrypt and base64 encode
    return encryptState(state)
}
```

### Token Validation

```go
func validateIDToken(token string, config *OIDCConfig) (*Claims, error) {
    // Fetch JWKS from provider
    // Validate signature
    // Check issuer, audience, expiry
    // Extract claims
}
```

---

## 9. Database Changes

### Settings Table Usage

No schema changes needed. SSO config stored as JSON in existing `settings` table:

```sql
INSERT INTO settings (key, value)
VALUES ('sso_config', '{"enabled": true, "provider": "oidc", ...}');
```

### Optional: Track SSO Sessions

```sql
-- Migration v27 (optional)
ALTER TABLE user_sessions
ADD COLUMN auth_method VARCHAR(20) DEFAULT 'password',
ADD COLUMN sso_subject VARCHAR(255);

-- auth_method: 'password', 'sso_oidc', 'sso_saml', 'magic_link'
```

---

## 10. Implementation Plan

### Phase 1: Core SSO Infrastructure

1. Add OIDC dependencies
   ```
   go get github.com/coreos/go-oidc/v3
   go get golang.org/x/oauth2
   ```

2. Create domain model (`internal/domain/sso.go`)

3. Create SSO service (`internal/service/sso_service.go`)
   - ConfigureSSO
   - GetSSOConfig
   - ValidateOIDCConfig
   - GetAuthorizationURL
   - HandleCallback

4. Add settings repository methods
   - GetSSOConfig
   - SaveSSOConfig

### Phase 2: Auth Flow

1. Add HTTP handlers (`internal/http/sso_handler.go`)
   - GET /api/auth.ssoConfig
   - GET /api/auth.sso.authorize
   - GET /api/auth.sso.callback

2. Extend auth service for SSO user provisioning

3. Integrate with existing session management

### Phase 3: Admin Configuration

1. Add admin handlers
   - POST /api/admin.sso.configure
   - GET /api/admin.sso.config
   - POST /api/admin.sso.test
   - DELETE /api/admin.sso.config

2. Frontend: Admin SSO settings page

### Phase 4: Frontend Integration

1. Login page SSO button
2. Admin settings UI for SSO configuration
3. User profile: show auth method

---

## 11. Recommendations

### 11.1 Start with OIDC Only, Skip SAML Initially

OIDC covers 90%+ of enterprise IdPs (Azure AD, Okta, Google Workspace, OneLogin all support it). SAML adds significant complexity with XML parsing, signature validation, and metadata management. Add SAML later only if customers explicitly require it.

### 11.2 Use Discovery URL, Avoid Manual Configuration

```go
// Recommended - auto-discovers all endpoints
DiscoveryURL: "https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration"

// Avoid - error-prone, maintenance burden
AuthorizationURL: "...",
TokenURL: "...",
JwksURL: "...",
```

Discovery URL automatically fetches and caches all endpoints, JWKS, and supported scopes. Manual configuration should only be a fallback for non-compliant providers.

### 11.3 Enforce SSO Option

Add a "disable password login" toggle. Many enterprises require this for compliance (SOC 2, ISO 27001):

```go
EnforceSSO: true  // Hides password form entirely
```

When enabled:
- Login page shows only "Login with SSO" button
- Password reset is disabled
- API rejects password-based authentication

### 11.4 Keep First User as Password-Based Admin

Chicken-and-egg problem: someone needs to configure SSO before SSO works.

```
1. First admin creates account with password (during initial setup)
2. Admin configures SSO via admin panel
3. Admin can optionally enable "enforce SSO"
4. First admin retains password access as emergency fallback
```

Consider adding an "emergency admin bypass" that allows the first admin to always use password, even when SSO is enforced. This prevents lockouts if IdP goes down.

### 11.5 Test Connection Button

Before saving SSO config, let admin verify it works:

```http
POST /api/admin.sso.test
→ Attempts OIDC discovery
→ Validates client credentials (if possible)
→ Returns success/failure with clear error message
```

Example responses:
```json
// Success
{
  "success": true,
  "provider_name": "Microsoft Azure AD",
  "issuer": "https://login.microsoftonline.com/...",
  "supported_scopes": ["openid", "email", "profile"]
}

// Failure
{
  "success": false,
  "error": "invalid_client",
  "message": "Client ID not found. Verify the application is registered in Azure AD."
}
```

### 11.6 SSO-Aware Invitation Emails

When SSO is enabled, invitation emails should reflect this:

**Without SSO:**
> "You've been invited to join [Workspace]. Click below to create your account."

**With SSO:**
> "You've been invited to join [Workspace]. Click below and sign in with your company credentials."

Implementation:
```go
func (s *EmailService) SendInvitation(invitation *Invitation) error {
    ssoConfig, _ := s.settingsRepo.GetSSOConfig(ctx)

    template := "invitation_password"
    if ssoConfig != nil && ssoConfig.Enabled {
        template = "invitation_sso"
    }

    return s.sendEmail(template, invitation)
}
```

### 11.7 Audit Logging for Compliance

Enterprise customers need audit trails. Log all SSO events:

```go
// Successful login
s.auditLog.Record(ctx, AuditEvent{
    Type:      "sso_login_success",
    UserID:    user.ID,
    Email:     claims.Email,
    IPAddress: req.RemoteAddr,
    Metadata: map[string]string{
        "idp_subject": claims.Subject,
        "idp_issuer":  claims.Issuer,
    },
})

// Failed login
s.auditLog.Record(ctx, AuditEvent{
    Type:      "sso_login_failed",
    Email:     claims.Email,
    IPAddress: req.RemoteAddr,
    Metadata: map[string]string{
        "reason": "no_invitation",
    },
})

// Config changes
s.auditLog.Record(ctx, AuditEvent{
    Type:   "sso_config_changed",
    UserID: admin.ID,
    Metadata: map[string]string{
        "action": "enabled",
    },
})
```

### 11.8 Grace Period for SSO Enforcement

When enabling `enforce_sso`, show a warning and consider a delay:

```
⚠️ Warning: Password login will be disabled for all users.

Before enabling:
• Ensure SSO configuration is tested and working
• Verify all users can authenticate via your Identity Provider
• The first admin will retain emergency password access

[ ] I understand. Enable SSO enforcement.
```

Optionally implement a 24-hour delay before enforcement takes effect, allowing time to catch configuration issues.

### 11.9 Handle IdP Downtime Gracefully

When the IdP is unavailable:

```go
func (s *SSOService) Authorize(ctx context.Context) (string, error) {
    // Check IdP health before redirecting
    if err := s.checkIdPHealth(ctx); err != nil {
        return "", &SSOError{
            Code:    "idp_unavailable",
            Message: "Identity provider is temporarily unavailable. Please try again or contact IT.",
        }
    }
    // ...
}
```

Display user-friendly error messages, not technical OIDC errors.

### 11.10 Session Lifetime Alignment

Consider aligning session lifetime with IdP token lifetime:

```go
type SSOSettings struct {
    // ...
    SessionLifetime    string `json:"session_lifetime"`     // "idp" or custom duration
    RefreshWithIdP     bool   `json:"refresh_with_idp"`     // Re-validate with IdP on refresh
}
```

Options:
- **"idp"**: Session expires when ID token expires
- **Custom duration**: Fixed session length (e.g., "8h", "24h")
- **Refresh with IdP**: Periodically re-validate user is still active in IdP

---

## 12. Priority Matrix

| Priority | Feature | Reason |
|----------|---------|--------|
| **P0** | OIDC auth flow | Core functionality |
| **P0** | Invitation-only provisioning | Primary requirement |
| **P0** | Discovery URL support | Standard OIDC |
| **P1** | Admin config UI | Usability |
| **P1** | Test connection button | Prevents lockouts |
| **P1** | SSO-aware invitation emails | User experience |
| **P2** | Enforce SSO toggle | Enterprise compliance |
| **P2** | Audit logging | Enterprise requirement |
| **P2** | Emergency admin bypass | Disaster recovery |
| **P3** | Session lifetime alignment | Advanced feature |
| **P3** | SAML support | Only if customer demand |

---

## 13. Files to Create/Modify

### New Files

| File | Purpose |
|------|---------|
| `internal/domain/sso.go` | SSO domain models |
| `internal/service/sso_service.go` | SSO business logic |
| `internal/http/sso_handler.go` | SSO HTTP endpoints |

### Modified Files

| File | Changes |
|------|---------|
| `internal/repository/settings_postgres.go` | Add SSO config methods |
| `internal/service/auth_service.go` | SSO user provisioning |
| `internal/http/router.go` | Register SSO routes |
| `config/config.go` | Version bump for migration |

---

## 14. Configuration Example

### Azure AD Setup

```json
{
  "enabled": true,
  "enforce_sso": false,
  "provider": "oidc",
  "oidc": {
    "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "client_secret": "your-client-secret",
    "discovery_url": "https://login.microsoftonline.com/your-tenant-id/v2.0/.well-known/openid-configuration",
    "scopes": ["openid", "email", "profile"]
  },
  "auto_provision": true,
  "require_invitation": true,
  "allowed_domains": ["yourcompany.com"],
  "default_role": "member"
}
```

### Okta Setup

```json
{
  "enabled": true,
  "provider": "oidc",
  "oidc": {
    "client_id": "0oaxxxxxxxxxxxxxxxx",
    "client_secret": "your-client-secret",
    "discovery_url": "https://yourcompany.okta.com/.well-known/openid-configuration",
    "scopes": ["openid", "email", "profile"]
  },
  "auto_provision": true,
  "require_invitation": false,
  "allowed_domains": ["yourcompany.com"]
}
```

---

## 15. Comparison: Server vs Workspace Level

| Aspect | Server-Level (Chosen) | Workspace-Level |
|--------|----------------------|-----------------|
| Config location | Global `settings` table | `workspaces.settings` |
| Admin | Instance admin / IT | Workspace owner |
| Use case | Enterprise self-hosted | Multi-tenant SaaS |
| Complexity | Simpler | More complex |
| User experience | Consistent across workspaces | Per-workspace SSO |

**Decision: Server-level** is correct for "each company has its own deployment" model.

---

## 16. Conclusion

### Feasibility: HIGH

Server-level SSO for enterprise self-hosted deployments is straightforward to implement:

| Requirement | Status |
|-------------|--------|
| Storage mechanism (settings table) | Exists |
| Encryption infrastructure | Exists |
| Session management | Exists |
| Invitation system | Exists |
| User provisioning patterns | Exists |

### Key Benefits

- **Simple for IT:** One configuration for entire instance
- **Secure:** Leverages existing encryption patterns
- **Flexible:** Supports invitation-only or open provisioning
- **Standard:** Uses OIDC, compatible with major IdPs

### Next Steps

1. Approve this architecture
2. Implement Phase 1 (Core Infrastructure)
3. Test with Azure AD / Okta
4. Add SAML support if needed (Phase 5)

# OAuth OIDC Workspace-Level Support - Feasibility Evaluation

**Date:** 2026-01-24
**Project:** Notifuse3
**Scope:** Evaluate OAuth OIDC support at workspace level with configuration stored in workspace settings

---

## Executive Summary

**Verdict: FEASIBLE**

The Notifuse3 codebase is well-architected for implementing OAuth OIDC support at the workspace level. The existing JSONB-based settings storage pattern, encryption infrastructure, and integration framework provide a solid foundation for this feature.

---

## 1. Current Architecture Analysis

### Technology Stack
- **Backend:** Go 1.23.x with clean architecture
- **Frontend:** React 18.2.0 + TypeScript 5.2.2 (Vite)
- **Database:** PostgreSQL 17 with JSONB support
- **Auth:** JWT-based with `golang-jwt/jwt/v5`

### Workspace Settings Storage

Current pattern in `internal/domain/workspace.go`:

```go
type WorkspaceSettings struct {
    WebsiteURL                   string              `json:"website_url,omitempty"`
    Timezone                     string              `json:"timezone"`
    FileManager                  FileManagerSettings `json:"file_manager,omitempty"`
    EncryptedSecretKey           string              `json:"encrypted_secret_key,omitempty"`
    // ... other fields stored as JSON in database
}
```

**Storage:** `workspaces` table, `settings` JSONB column
**Encryption:** Sensitive fields encrypted with global secret key via `BeforeSave()`/`AfterLoad()` pattern

### Existing OAuth2 (Limited)
- Only for email provider authentication (SMTP XOAUTH2)
- Supports Microsoft Azure and Google
- Located in `service/oauth2_token_service.go`
- **No user-facing OAuth/OIDC authentication currently exists**

---

## 2. Feasibility Assessment

### Why This Is Feasible

| Factor | Assessment | Notes |
|--------|------------|-------|
| **Settings Storage** | Excellent | JSONB column already supports complex nested structures |
| **Encryption Pattern** | Excellent | Existing `BeforeSave()`/`AfterLoad()` pattern for secrets |
| **Integration Pattern** | Excellent | Flexible `Integrations` array model is extensible |
| **Migration System** | Good | Version-based migrations support schema changes |
| **Permission System** | Excellent | Granular workspace permissions already exist |
| **Workspace Isolation** | Excellent | Clean workspace-scoped architecture |

### Key Enablers

1. **JSONB Flexibility:** Adding new fields to `WorkspaceSettings` requires no schema migration
2. **Encryption Ready:** Global secret key infrastructure handles sensitive data
3. **Service Pattern:** Clean domain/service/repository/handler separation
4. **API Style:** RPC-style endpoints easy to extend

---

## 3. Proposed Data Model

### OAuth OIDC Settings Structure

```go
type OAuthOIDCSettings struct {
    Enabled               bool              `json:"enabled"`
    Provider              string            `json:"provider"`  // google, azure, okta, auth0, generic
    ClientID              string            `json:"client_id"`
    EncryptedClientSecret string            `json:"encrypted_client_secret,omitempty"`

    // OIDC Discovery (preferred)
    DiscoveryURL          string            `json:"discovery_url,omitempty"`

    // Manual endpoints (fallback)
    AuthorizationURL      string            `json:"authorization_url,omitempty"`
    TokenURL              string            `json:"token_url,omitempty"`
    UserInfoURL           string            `json:"user_info_url,omitempty"`
    JwksURL               string            `json:"jwks_url,omitempty"`

    // Configuration
    Scopes                []string          `json:"scopes"`
    AllowedDomains        []string          `json:"allowed_domains,omitempty"`
    AutoProvision         bool              `json:"auto_provision"`
    DefaultRole           string            `json:"default_role"`  // owner, member
    DefaultPermissions    UserPermissions   `json:"default_permissions,omitempty"`

    // Claim mappings
    EmailClaim            string            `json:"email_claim,omitempty"`   // default: email
    NameClaim             string            `json:"name_claim,omitempty"`    // default: name
    GroupsClaim           string            `json:"groups_claim,omitempty"`  // optional

    // Metadata
    CreatedAt             time.Time         `json:"created_at"`
    UpdatedAt             time.Time         `json:"updated_at"`

    // Runtime only (not stored)
    ClientSecret          string            `json:"-"`
}
```

### Extended WorkspaceSettings

```go
type WorkspaceSettings struct {
    // ... existing fields ...

    // New: OAuth OIDC configuration
    OAuthOIDC             *OAuthOIDCSettings `json:"oauth_oidc,omitempty"`
}
```

---

## 4. Storage Options Comparison

### Option A: Store in Existing `settings` JSONB (Recommended)

**Pros:**
- No schema migration required
- Follows existing pattern
- Settings retrieved with workspace load
- Encryption handled by existing lifecycle

**Cons:**
- All settings loaded together (minor performance concern)

**Implementation:**
```go
// In workspace.go - add to WorkspaceSettings
OAuthOIDC *OAuthOIDCSettings `json:"oauth_oidc,omitempty"`
```

### Option B: Separate JSONB Column

**Pros:**
- Isolated from other settings
- Can query independently

**Cons:**
- Requires schema migration
- Additional repository methods
- Breaks consistency with current pattern

### Option C: Separate Table

**Pros:**
- Full relational model
- Easy to query/report

**Cons:**
- Major architectural change
- Additional JOINs
- Foreign key management
- Breaks JSONB pattern

**Recommendation: Option A** - Maintains consistency with existing architecture

---

## 5. Implementation Approach

### Phase 1: Core Infrastructure

1. **Add Go OIDC Library**
   ```
   go get github.com/coreos/go-oidc/v3
   go get golang.org/x/oauth2
   ```

2. **Extend Domain Model**
   - Add `OAuthOIDCSettings` struct to `internal/domain/workspace.go`
   - Add encryption methods for client secret
   - Add validation methods

3. **Extend Repository**
   - No changes needed (JSONB handles it)

### Phase 2: Service Layer

1. **Create OIDC Service** (`internal/service/oidc_service.go`)
   - Configure workspace OIDC
   - Get OIDC configuration
   - Disable OIDC
   - Validate provider settings

2. **Extend Auth Service**
   - OIDC authorize flow
   - OIDC callback handling
   - User provisioning
   - Token validation

### Phase 3: HTTP Layer

1. **New Endpoints**
   ```
   POST   /api/workspaces.configureOIDC
   GET    /api/workspaces.getOIDCConfig
   DELETE /api/workspaces.disableOIDC

   GET    /api/auth.oidc.authorize
   POST   /api/auth.oidc.callback
   POST   /api/auth.oidc.logout
   ```

2. **Handler Implementation**
   - OIDC configuration handler
   - OAuth flow handlers

### Phase 4: User Provisioning

1. **Auto-provisioning Logic**
   - Check if user exists by email
   - Create user if `auto_provision` enabled
   - Assign default role/permissions
   - Link to workspace

2. **Permission Assignment**
   - Apply `default_permissions` from OIDC config
   - Optional: Map OIDC groups to permissions

---

## 6. Authentication Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     OAuth OIDC Flow                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. User clicks "Login with SSO" on workspace login page        │
│                         │                                        │
│                         ▼                                        │
│  2. GET /api/auth.oidc.authorize?workspace_id=xxx               │
│     - Load workspace OIDC config                                │
│     - Generate state (workspace_id + nonce)                     │
│     - Redirect to provider authorization URL                    │
│                         │                                        │
│                         ▼                                        │
│  3. User authenticates with Identity Provider                   │
│                         │                                        │
│                         ▼                                        │
│  4. Provider redirects to /api/auth.oidc.callback               │
│     - Validate state parameter                                  │
│     - Exchange code for tokens                                  │
│     - Validate ID token                                         │
│     - Extract user claims (email, name)                         │
│                         │                                        │
│                         ▼                                        │
│  5. User Provisioning                                           │
│     - Check allowed_domains                                     │
│     - Find or create user                                       │
│     - Assign to workspace with default_role                     │
│     - Create session                                            │
│                         │                                        │
│                         ▼                                        │
│  6. Return JWT token to client                                  │
│     - Redirect to dashboard with token                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 7. Security Considerations

### Must Implement

| Security Measure | Implementation |
|-----------------|----------------|
| Client Secret Encryption | Use existing `pkg/crypto` with global secret key |
| State Parameter | Cryptographic random + workspace ID + expiration |
| PKCE | Use code_challenge/code_verifier for public clients |
| Token Validation | Validate JWT signature using provider JWKS |
| Domain Restriction | Check email domain against `allowed_domains` |
| HTTPS Only | Enforce in redirect URIs |
| Rate Limiting | Implement on auth endpoints |

### Encryption Pattern (Existing)

```go
func (s *OAuthOIDCSettings) BeforeSave(secretKey []byte) error {
    if s.ClientSecret != "" {
        encrypted, err := crypto.Encrypt([]byte(s.ClientSecret), secretKey)
        if err != nil {
            return err
        }
        s.EncryptedClientSecret = base64.StdEncoding.EncodeToString(encrypted)
        s.ClientSecret = ""
    }
    return nil
}

func (s *OAuthOIDCSettings) AfterLoad(secretKey []byte) error {
    if s.EncryptedClientSecret != "" {
        decoded, err := base64.StdEncoding.DecodeString(s.EncryptedClientSecret)
        if err != nil {
            return err
        }
        decrypted, err := crypto.Decrypt(decoded, secretKey)
        if err != nil {
            return err
        }
        s.ClientSecret = string(decrypted)
    }
    return nil
}
```

---

## 8. Database Changes

### Required Migration (Minimal)

No schema migration required if using Option A (settings JSONB column).

Optional migration for session enhancement:

```sql
-- v27 migration (optional)
ALTER TABLE user_sessions
ADD COLUMN auth_method VARCHAR(20) DEFAULT 'password',
ADD COLUMN oidc_provider VARCHAR(50),
ADD COLUMN oidc_subject VARCHAR(255);

CREATE INDEX idx_user_sessions_oidc ON user_sessions(oidc_provider, oidc_subject)
WHERE oidc_provider IS NOT NULL;
```

---

## 9. API Specification

### Configure OIDC

```http
POST /api/workspaces.configureOIDC
Authorization: Bearer <token>
Content-Type: application/json

{
  "workspace_id": "ws_xxx",
  "provider": "azure",
  "client_id": "abc123",
  "client_secret": "secret",
  "discovery_url": "https://login.microsoftonline.com/{tenant}/.well-known/openid-configuration",
  "scopes": ["openid", "email", "profile"],
  "allowed_domains": ["company.com"],
  "auto_provision": true,
  "default_role": "member",
  "default_permissions": {
    "contacts": {"read": true, "write": false},
    "templates": {"read": true, "write": true}
  }
}
```

### Get OIDC Config (Redacted)

```http
GET /api/workspaces.getOIDCConfig?workspace_id=ws_xxx
Authorization: Bearer <token>

Response:
{
  "enabled": true,
  "provider": "azure",
  "client_id": "abc123",
  "client_secret_set": true,  // boolean, not actual secret
  "discovery_url": "https://...",
  "allowed_domains": ["company.com"],
  "auto_provision": true,
  "default_role": "member"
}
```

---

## 10. Provider Support Matrix

| Provider | Discovery URL Pattern | Notes |
|----------|----------------------|-------|
| Google | `https://accounts.google.com/.well-known/openid-configuration` | Standard OIDC |
| Azure AD | `https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration` | Tenant-specific |
| Okta | `https://{domain}.okta.com/.well-known/openid-configuration` | Custom domains |
| Auth0 | `https://{tenant}.auth0.com/.well-known/openid-configuration` | Multi-tenant |
| Generic | User-provided | Any OIDC-compliant provider |

---

## 11. Frontend Changes

### Required UI Components

1. **Workspace Settings - SSO Section**
   - OIDC provider selection
   - Configuration form
   - Test connection button
   - Enable/disable toggle

2. **Login Page Enhancement**
   - "Login with SSO" button (workspace-specific)
   - SSO-only mode option

3. **User Management**
   - Indicate SSO-provisioned users
   - Show authentication method

---

## 12. Effort Estimation

| Component | Complexity | Files Affected |
|-----------|------------|----------------|
| Domain Model | Low | 1 (`workspace.go`) |
| OIDC Service | Medium | 1 new file |
| Auth Service Extension | Medium | 1 (`auth_service.go`) |
| HTTP Handlers | Medium | 2 files |
| Frontend Settings UI | Medium | 2-3 components |
| Frontend Login Flow | Low | 1 component |
| Testing | Medium | 4-5 test files |
| Documentation | Low | 1-2 files |

---

## 13. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Provider-specific quirks | Medium | Medium | Use discovery URL, test major providers |
| Token validation errors | Low | High | Comprehensive error handling, detailed logging |
| User provisioning conflicts | Medium | Medium | Clear email matching, duplicate handling |
| Secret key rotation | Low | High | Document rotation procedure |
| Session management complexity | Low | Medium | Leverage existing session infrastructure |

---

## 14. Testing Strategy

### Unit Tests
- OIDC settings validation
- Token parsing
- Claim extraction
- Permission mapping

### Integration Tests
- Full OAuth flow (with mock provider)
- User provisioning
- Configuration CRUD
- Error scenarios

### E2E Tests
- Real provider integration (staging)
- Login flow
- Settings configuration

---

## 15. Dependencies

### Go Packages

```go
require (
    github.com/coreos/go-oidc/v3 v3.x.x
    golang.org/x/oauth2 v0.x.x
)
```

### External Services
- OIDC Identity Provider (customer-provided)
- HTTPS callback URL (production requirement)

---

## 16. Conclusion

### Feasibility: HIGH

The Notifuse3 architecture is well-suited for OAuth OIDC at workspace level:

| Criterion | Status |
|-----------|--------|
| Storage mechanism ready | :white_check_mark: |
| Encryption infrastructure | :white_check_mark: |
| Migration system | :white_check_mark: |
| Service layer extensible | :white_check_mark: |
| API pattern established | :white_check_mark: |
| Permission system compatible | :white_check_mark: |

### Recommended Approach

1. Store OIDC config in existing `settings` JSONB column
2. Follow existing encryption pattern for client secrets
3. Extend auth service for OIDC flows
4. Add new HTTP handlers following RPC pattern
5. Support major providers via OIDC discovery

### Next Steps

1. Review and approve this evaluation
2. Create detailed implementation plan
3. Begin Phase 1 (Core Infrastructure)
4. Iterate through remaining phases

---

## Appendix: File References

| Component | Path |
|-----------|------|
| Workspace Domain | `internal/domain/workspace.go` |
| Workspace Service | `internal/service/workspace_service.go` |
| Auth Service | `internal/service/auth_service.go` |
| OAuth Token Service (reference) | `internal/service/oauth2_token_service.go` |
| Database Schema | `internal/database/schema/system_tables.go` |
| Migrations | `internal/migrations/` |
| Config | `config/config.go` |

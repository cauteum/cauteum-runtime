package idp

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// OIDCConfig configures issuer-backed JWT validation (OpenShell-compatible subset).
type OIDCConfig struct {
	Issuer   string
	Audience string // optional aud claim
	// AllowInsecureHTTP permits http:// loopback issuers (local Dex/Keycloak).
	AllowInsecureHTTP bool
	HTTPClient        *http.Client
	JWKSCacheTTL      time.Duration
}

// OIDC is an Adapter that validates Bearer JWTs via issuer JWKS.
type OIDC struct {
	cfg     OIDCConfig
	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
	jwksURI string
}

// NewOIDC builds a validator. Discovery runs lazily on first Validate.
func NewOIDC(cfg OIDCConfig) (*OIDC, error) {
	cfg.Issuer = strings.TrimRight(strings.TrimSpace(cfg.Issuer), "/")
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("oidc: issuer required")
	}
	if err := validateIssuerURL(cfg.Issuer, cfg.AllowInsecureHTTP); err != nil {
		return nil, err
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	if cfg.JWKSCacheTTL <= 0 {
		cfg.JWKSCacheTTL = 10 * time.Minute
	}
	return &OIDC{cfg: cfg, keys: map[string]*rsa.PublicKey{}}, nil
}

// Issuer returns the configured issuer.
func (o *OIDC) Issuer() string { return o.cfg.Issuer }

// Token is not used for gateway validation adapters.
func (o *OIDC) Token(context.Context) (string, error) {
	return "", fmt.Errorf("%w: use CLI PKCE login", ErrNotImplemented)
}

// Validate verifies a JWT access/id token against JWKS.
func (o *OIDC) Validate(ctx context.Context, token string) (Claims, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return Claims{}, fmt.Errorf("oidc: empty token")
	}
	if err := o.ensureKeys(ctx); err != nil {
		return Claims{}, err
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, fmt.Errorf("oidc: malformed jwt")
	}
	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, fmt.Errorf("oidc: header: %w", err)
	}
	var hdr struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		return Claims{}, fmt.Errorf("oidc: header json: %w", err)
	}
	if hdr.Alg != "RS256" {
		return Claims{}, fmt.Errorf("oidc: unsupported alg %q (want RS256)", hdr.Alg)
	}
	if hdr.Typ != "" && hdr.Typ != "JWT" {
		return Claims{}, fmt.Errorf("oidc: unsupported typ %q (want JWT)", hdr.Typ)
	}
	o.mu.Lock()
	pub := o.keys[hdr.Kid]
	if pub == nil && len(o.keys) == 1 {
		for _, k := range o.keys {
			pub = k
		}
	}
	o.mu.Unlock()
	if pub == nil {
		// force refresh once for unknown kid
		o.mu.Lock()
		o.fetched = time.Time{}
		o.mu.Unlock()
		if err := o.ensureKeys(ctx); err != nil {
			return Claims{}, err
		}
		o.mu.Lock()
		pub = o.keys[hdr.Kid]
		o.mu.Unlock()
		if pub == nil {
			return Claims{}, fmt.Errorf("oidc: unknown kid %q", hdr.Kid)
		}
	}
	payload, err := verifyRS256(parts[0]+"."+parts[1], parts[2], pub)
	if err != nil {
		return Claims{}, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Claims{}, fmt.Errorf("oidc: claims: %w", err)
	}
	iss, _ := claims["iss"].(string)
	if strings.TrimRight(iss, "/") != o.cfg.Issuer {
		return Claims{}, fmt.Errorf("oidc: issuer mismatch")
	}
	if o.cfg.Audience != "" {
		if !audienceOK(claims["aud"], o.cfg.Audience) {
			return Claims{}, fmt.Errorf("oidc: audience mismatch")
		}
	} else if _, supplied := claims["aud"]; supplied {
		slog.Warn("oidc audience not configured; token audience is unchecked")
	}
	if err := validateTokenTimes(claims, time.Now()); err != nil {
		return Claims{}, err
	}
	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	return Claims{Subject: sub, Issuer: iss, Email: email, Raw: claims}, nil
}

const tokenClockLeeway = 90 * time.Second

func validateTokenTimes(claims map[string]any, now time.Time) error {
	for _, field := range []string{"exp", "nbf", "iat"} {
		value, exists := claims[field]
		if !exists {
			continue
		}
		instant, ok := numericTime(value)
		if !ok {
			return fmt.Errorf("oidc: invalid %s claim", field)
		}
		switch field {
		case "exp":
			if now.After(instant.Add(tokenClockLeeway)) {
				return fmt.Errorf("oidc: token expired")
			}
		case "nbf", "iat":
			if now.Add(tokenClockLeeway).Before(instant) {
				return fmt.Errorf("oidc: token %s is in the future", field)
			}
		}
	}
	return nil
}

func (o *OIDC) ensureKeys(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.keys) > 0 && time.Since(o.fetched) < o.cfg.JWKSCacheTTL {
		return nil
	}
	jwksURI := o.jwksURI
	if jwksURI == "" {
		disc, err := Discover(ctx, o.cfg.Issuer, o.cfg.HTTPClient)
		if err != nil {
			return err
		}
		jwksURI = disc.JWKSURI
		o.jwksURI = jwksURI
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return err
	}
	res, err := o.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("oidc jwks: %w", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	if res.StatusCode >= 300 {
		return fmt.Errorf("oidc jwks: %s", res.Status)
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("oidc jwks parse: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.N == "" || k.E == "" {
			continue
		}
		pub, err := jwkToRSA(k)
		if err != nil {
			continue
		}
		kid := k.Kid
		if kid == "" {
			kid = fmt.Sprintf("key-%d", len(keys))
		}
		keys[kid] = pub
	}
	if len(keys) == 0 {
		return fmt.Errorf("oidc jwks: no usable RSA keys")
	}
	o.keys = keys
	o.fetched = time.Now()
	return nil
}

// Discovery is the OpenID provider metadata subset we need.
type Discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	DeviceAuthEndpoint    string `json:"device_authorization_endpoint"`
}

// Discover fetches /.well-known/openid-configuration.
func Discover(ctx context.Context, issuer string, client *http.Client) (Discovery, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	url := issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Discovery{}, err
	}
	res, err := client.Do(req)
	if err != nil {
		return Discovery{}, fmt.Errorf("oidc discovery: %w", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if err != nil {
		return Discovery{}, err
	}
	if res.StatusCode >= 300 {
		return Discovery{}, fmt.Errorf("oidc discovery: %s", res.Status)
	}
	var d Discovery
	if err := json.Unmarshal(body, &d); err != nil {
		return Discovery{}, err
	}
	if strings.TrimRight(d.Issuer, "/") != issuer {
		return Discovery{}, fmt.Errorf("oidc discovery issuer mismatch: want %s got %s", issuer, d.Issuer)
	}
	return d, nil
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

func jwkToRSA(k jwk) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	var eInt int
	for _, b := range eb {
		eInt = eInt<<8 + int(b)
	}
	if eInt == 0 {
		eInt = 65537
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: eInt}, nil
}

func audienceOK(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func numericTime(v any) (time.Time, bool) {
	switch n := v.(type) {
	case float64:
		return time.Unix(int64(n), 0), true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(i, 0), true
	default:
		return time.Time{}, false
	}
}

func validateIssuerURL(issuer string, allowHTTP bool) error {
	if strings.HasPrefix(issuer, "https://") {
		return nil
	}
	if allowHTTP && strings.HasPrefix(issuer, "http://") {
		host := strings.TrimPrefix(issuer, "http://")
		if i := strings.IndexAny(host, "/:"); i >= 0 {
			host = host[:i]
		}
		if host == "127.0.0.1" || host == "localhost" || host == "::1" {
			return nil
		}
		return fmt.Errorf("oidc: http issuer only allowed on loopback")
	}
	return fmt.Errorf("oidc: issuer must be https:// (or http:// loopback with AllowInsecureHTTP)")
}

var _ Adapter = (*OIDC)(nil)

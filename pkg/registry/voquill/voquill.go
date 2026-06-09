// Package voquill provides Voquill-native authentication for pulling private
// agent images from Google Artifact Registry.
//
// Voquill issues no static registry credentials. Instead, an agent holds a
// Voquill API key (a "vlk_" key whose role carries the registry:pull
// permission) and exchanges it, on demand, for a short-lived (~1h) Artifact
// Registry access token via the Voquill cloud API:
//
//	POST {cloud_url}/v1/agent/registry-token
//	Authorization: Bearer vlk_...
//
//	200 OK
//	{
//	  "registry":   "us-central1-docker.pkg.dev",
//	  "username":   "oauth2accesstoken",
//	  "token":      "<short-lived GCP access token>",
//	  "expires_at": "2026-06-08T15:30:00Z"
//	}
//
// This package mirrors the behaviour of Voquill's standalone credential
// refresher (ghcr.io/voquill/cred) but folds it directly into Watchtower, so a
// site needs only Watchtower plus a vlk_ key — no sidecar and no config.json on
// disk. Tokens are cached in memory and refreshed shortly before they expire.
package voquill

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/nicholas-fedor/watchtower/internal/meta"
	"github.com/nicholas-fedor/watchtower/pkg/registry/auth"
)

// Configuration keys read from Viper (bound to the equivalent environment
// variables in internal/flags).
const (
	// KeyAPIKey holds the Voquill API key (vlk_...) used to mint registry tokens.
	KeyAPIKey = "WATCHTOWER_VOQUILL_API_KEY" //nolint:gosec // G101: Viper config key name, not a credential
	// KeyCloudURL holds the base URL of the Voquill cloud API (e.g. https://api.voquill.com).
	KeyCloudURL = "WATCHTOWER_VOQUILL_CLOUD_URL"
	// KeyRegistry holds the registry host Voquill auth applies to.
	KeyRegistry = "WATCHTOWER_VOQUILL_REGISTRY"
)

const (
	// DefaultRegistry is the Artifact Registry host Voquill agent images live in.
	DefaultRegistry = "us-central1-docker.pkg.dev"
	// tokenPath is the cloud API path that mints a registry token.
	tokenPath = "/v1/agent/registry-token" //nolint:gosec // G101: URL path, not a credential
	// refreshSkew triggers a refresh this long before a token actually expires,
	// so an in-flight pull never races the expiry.
	refreshSkew = 5 * time.Minute
	// fallbackTTL is used when the API omits a usable expires_at.
	fallbackTTL = 30 * time.Minute
	// requestTimeout bounds a single mint request.
	requestTimeout = 30 * time.Second
	// maxErrBody caps how much of an error response body we log.
	maxErrBody = 1024
)

// errMintFailed indicates the Voquill cloud API did not return a usable token.
var errMintFailed = errors.New("voquill: failed to mint registry token")

// Credentials are registry credentials minted by Voquill, in the same shape as
// a Docker auth entry (oauth2accesstoken + a short-lived token).
type Credentials struct {
	Username string
	Password string
}

// tokenResponse mirrors the JSON returned by POST /v1/agent/registry-token.
type tokenResponse struct {
	Registry  string    `json:"registry"`
	Username  string    `json:"username"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// cachedToken is a minted token held in memory until shortly before it expires.
type cachedToken struct {
	username  string
	secret    string
	expiresAt time.Time
}

// Package-level token cache. Mirrors the cached-client pattern used elsewhere in
// the registry packages; protected by mu for concurrent scans.
var (
	cacheMu sync.Mutex
	cache   *cachedToken

	httpClient = &http.Client{
		Timeout:   requestTimeout,
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment},
	}
)

// apiKey returns the configured Voquill API key, trimmed.
func apiKey() string {
	return strings.TrimSpace(viper.GetString(KeyAPIKey))
}

// cloudURL returns the configured Voquill cloud API base URL, trimmed of any
// trailing slash so it can be joined with tokenPath cleanly.
func cloudURL() string {
	return strings.TrimRight(strings.TrimSpace(viper.GetString(KeyCloudURL)), "/")
}

// registryHost returns the registry host Voquill auth applies to, defaulting to
// DefaultRegistry when unset.
func registryHost() string {
	if host := strings.TrimSpace(viper.GetString(KeyRegistry)); host != "" {
		return host
	}

	return DefaultRegistry
}

// Enabled reports whether Voquill authentication is configured (both an API key
// and a cloud URL are present).
func Enabled() bool {
	return apiKey() != "" && cloudURL() != ""
}

// CredentialsFor returns Voquill-minted registry credentials for imageName.
//
// The boolean result reports whether Voquill auth applies to this image: it is
// true only when Voquill is configured and imageName targets the Voquill
// registry. When it is false, the caller should fall back to its other
// credential sources (environment variables, Docker config). When it is true,
// the error is non-nil only if a token could not be obtained.
//
// Parameters:
//   - ctx: Context for request lifecycle control.
//   - imageName: Image reference (e.g. "us-central1-docker.pkg.dev/proj/agents/lab_agent").
//
// Returns:
//   - Credentials: Minted oauth2accesstoken credentials when applicable.
//   - bool: True if Voquill auth applies to imageName.
//   - error: Non-nil only when Voquill applies but minting failed.
func CredentialsFor(ctx context.Context, imageName string) (Credentials, bool, error) {
	if !Enabled() {
		return Credentials{}, false, nil
	}

	// Determine the image's registry host; if we can't, let other sources try.
	host, err := auth.GetRegistryAddress(imageName)
	if err != nil {
		logrus.WithError(err).
			WithField("image_ref", imageName).
			Debug("Voquill: could not determine registry host; skipping")

		return Credentials{}, false, nil
	}

	// Only handle images on the configured Voquill registry.
	if !strings.EqualFold(host, registryHost()) {
		return Credentials{}, false, nil
	}

	tok, err := token(ctx)
	if err != nil {
		return Credentials{}, true, err
	}

	return Credentials{Username: tok.username, Password: tok.secret}, true, nil
}

// token returns a valid registry token, minting a fresh one when the cache is
// empty or close to expiry. A failed refresh falls back to a still-valid cached
// token when one is available, so a transient cloud blip does not break pulls.
func token(ctx context.Context) (cachedToken, error) {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	if cache != nil && time.Until(cache.expiresAt) > refreshSkew {
		return *cache, nil
	}

	fresh, err := mint(ctx)
	if err != nil {
		if cache != nil && time.Now().Before(cache.expiresAt) {
			logrus.WithError(err).
				Warn("Voquill: token refresh failed; reusing still-valid cached token")

			return *cache, nil
		}

		return cachedToken{}, err
	}

	cache = &fresh

	logrus.WithField("expires_at", fresh.expiresAt.Format(time.RFC3339)).
		Debug("Voquill: minted registry token")

	return fresh, nil
}

// mint exchanges the configured API key for a fresh registry token via the
// Voquill cloud API.
func mint(ctx context.Context) (cachedToken, error) {
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	endpoint := cloudURL() + tokenPath

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, nil)
	if err != nil {
		return cachedToken{}, fmt.Errorf("%w: build request: %w", errMintFailed, err)
	}

	req.Header.Set("Authorization", "Bearer "+apiKey())
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", meta.UserAgent)

	resp, err := httpClient.Do(req)
	if err != nil {
		return cachedToken{}, fmt.Errorf("%w: %w", errMintFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Only error bodies are length-bounded; success bodies are read in full
		// below (a GCP access token alone is ~1KB).
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrBody+1))

		return cachedToken{}, fmt.Errorf(
			"%w: %s responded %s: %s",
			errMintFailed,
			endpoint,
			resp.Status,
			snippet(body),
		)
	}

	parsed := tokenResponse{}

	err = json.NewDecoder(resp.Body).Decode(&parsed)
	if err != nil {
		return cachedToken{}, fmt.Errorf("%w: decode response: %w", errMintFailed, err)
	}

	if parsed.Token == "" {
		return cachedToken{}, fmt.Errorf("%w: empty token in response", errMintFailed)
	}

	username := parsed.Username
	if username == "" {
		username = "oauth2accesstoken"
	}

	expiresAt := parsed.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(fallbackTTL)
	}

	return cachedToken{username: username, secret: parsed.Token, expiresAt: expiresAt}, nil
}

// snippet returns a single-line, length-bounded view of a response body for
// safe logging.
func snippet(body []byte) string {
	text := strings.TrimSpace(string(body))
	text = strings.ReplaceAll(text, "\n", " ")

	if len(text) > maxErrBody {
		return text[:maxErrBody] + "…"
	}

	return text
}

// ResetCache clears the in-memory token cache. It exists for tests and is safe
// to call at any time.
func ResetCache() {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	cache = nil
}

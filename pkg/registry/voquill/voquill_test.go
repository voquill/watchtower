package voquill_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/viper"

	"github.com/nicholas-fedor/watchtower/pkg/registry/voquill"
)

const (
	testKey   = "vlk_testkey"
	testImage = "us-central1-docker.pkg.dev/voquill/agents/lab_agent"
)

// longToken mimics a real GCP access token (~1KB+), guarding against truncating
// the success response body.
var longToken = "ya29." + strings.Repeat("aZ4bNp", 200)

// configure sets Voquill config for a test and clears it afterwards.
func configure(t *testing.T, apiKey, cloudURL, registry string) {
	t.Helper()
	viper.Set(voquill.KeyAPIKey, apiKey)
	viper.Set(voquill.KeyCloudURL, cloudURL)
	viper.Set(voquill.KeyRegistry, registry)
	voquill.ResetCache()

	t.Cleanup(func() {
		viper.Set(voquill.KeyAPIKey, "")
		viper.Set(voquill.KeyCloudURL, "")
		viper.Set(voquill.KeyRegistry, "")
		voquill.ResetCache()
	})
}

// tokenServer returns an httptest server that mints a token and counts hits.
func tokenServer(t *testing.T, hits *int32) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)

		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		if r.URL.Path != "/v1/agent/registry-token" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}

		if got := r.Header.Get("Authorization"); got != "Bearer "+testKey {
			t.Errorf("unexpected Authorization %q", got)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"registry": "us-central1-docker.pkg.dev",
			"username": "oauth2accesstoken",
			"token": "` + longToken + `",
			"expires_at": "` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `"
		}`))
	}))
}

func TestCredentialsFor_NotConfigured(t *testing.T) {
	configure(t, "", "", "")

	_, ok, err := voquill.CredentialsFor(context.Background(), testImage)
	if ok || err != nil {
		t.Fatalf("expected ok=false err=nil when unconfigured, got ok=%v err=%v", ok, err)
	}
}

func TestCredentialsFor_OtherRegistry(t *testing.T) {
	var hits int32

	srv := tokenServer(t, &hits)
	defer srv.Close()

	configure(t, testKey, srv.URL, "")

	// Image is on Docker Hub, not the Voquill registry: Voquill must not apply.
	_, ok, err := voquill.CredentialsFor(context.Background(), "docker.io/library/alpine")
	if ok || err != nil {
		t.Fatalf("expected ok=false err=nil for non-Voquill registry, got ok=%v err=%v", ok, err)
	}

	if hits != 0 {
		t.Fatalf("expected no token requests for non-Voquill registry, got %d", hits)
	}
}

func TestCredentialsFor_SuccessAndCaching(t *testing.T) {
	var hits int32

	srv := tokenServer(t, &hits)
	defer srv.Close()

	configure(t, testKey, srv.URL, "")

	creds, ok, err := voquill.CredentialsFor(context.Background(), testImage)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !ok {
		t.Fatal("expected Voquill auth to apply")
	}

	if creds.Username != "oauth2accesstoken" || creds.Password != longToken {
		t.Fatalf("unexpected credentials: user=%q passLen=%d", creds.Username, len(creds.Password))
	}

	// Second call within the token's lifetime must be served from cache.
	_, _, err = voquill.CredentialsFor(context.Background(), testImage)
	if err != nil {
		t.Fatalf("unexpected error on cached call: %v", err)
	}

	if hits != 1 {
		t.Fatalf("expected exactly 1 token request (cached after), got %d", hits)
	}
}

func TestCredentialsFor_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"detail":"minting disabled"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	configure(t, testKey, srv.URL, "")

	_, ok, err := voquill.CredentialsFor(context.Background(), testImage)
	if !ok {
		t.Fatal("expected Voquill auth to apply (it owns this registry)")
	}

	if err == nil {
		t.Fatal("expected an error when the cloud API returns 500")
	}
}

func TestCredentialsFor_CustomRegistry(t *testing.T) {
	var hits int32

	srv := tokenServer(t, &hits)
	defer srv.Close()

	configure(t, testKey, srv.URL, "registry.example.com")

	_, ok, err := voquill.CredentialsFor(
		context.Background(),
		"registry.example.com/team/app",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !ok {
		t.Fatal("expected Voquill auth to apply to the custom registry")
	}

	if hits != 1 {
		t.Fatalf("expected 1 token request, got %d", hits)
	}
}

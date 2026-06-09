package auth_test

import (
	"strings"
	"testing"

	"github.com/distribution/reference"

	"github.com/nicholas-fedor/watchtower/pkg/registry/auth"
)

// Google Artifact Registry's /v2/ ping returns a Bearer challenge with only a
// realm — no service. These tests verify Watchtower defaults the missing
// service to the registry host instead of failing.

const garImage = "us-central1-docker.pkg.dev/voquill/agents/lab_agent"

func TestProcessChallenge_DefaultsServiceToHost(t *testing.T) {
	header := `Bearer realm="https://us-central1-docker.pkg.dev/v2/token"`

	scope, realm, service, err := auth.ProcessChallenge(header, garImage)
	if err != nil {
		t.Fatalf("expected no error for service-less GAR challenge, got %v", err)
	}

	if service != "us-central1-docker.pkg.dev" {
		t.Errorf("expected service defaulted to registry host, got %q", service)
	}

	if realm != "https://us-central1-docker.pkg.dev/v2/token" {
		t.Errorf("unexpected realm %q", realm)
	}

	if scope != "" {
		t.Errorf("expected empty scope, got %q", scope)
	}
}

func TestProcessChallenge_MissingRealmStillErrors(t *testing.T) {
	header := `Bearer service="us-central1-docker.pkg.dev"`

	scope, realm, service, err := auth.ProcessChallenge(header, garImage)
	if err == nil {
		t.Fatalf(
			"expected an error when realm is missing (got scope=%q realm=%q service=%q)",
			scope, realm, service,
		)
	}
}

func TestGetAuthURL_DefaultsServiceToHost(t *testing.T) {
	ref, err := reference.ParseNormalizedNamed(garImage)
	if err != nil {
		t.Fatalf("failed to parse image: %v", err)
	}

	challenge := `Bearer realm="https://us-central1-docker.pkg.dev/v2/token"`

	authURL, err := auth.GetAuthURL(challenge, ref)
	if err != nil {
		t.Fatalf("expected GetAuthURL to succeed for service-less GAR challenge, got %v", err)
	}

	if authURL.Host != "us-central1-docker.pkg.dev" || authURL.Path != "/v2/token" {
		t.Errorf("unexpected auth URL host/path: %s", authURL.String())
	}

	query := authURL.Query()
	if got := query.Get("service"); got != "us-central1-docker.pkg.dev" {
		t.Errorf("expected service defaulted to registry host, got %q", got)
	}

	if got := query.Get("scope"); !strings.Contains(got, "repository:") ||
		!strings.HasSuffix(got, ":pull") {
		t.Errorf("unexpected scope %q", got)
	}
}

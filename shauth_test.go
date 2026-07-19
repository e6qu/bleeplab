package bleeplab

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestSHAUTHConfigRequiresCompleteHTTPSCoordinates(t *testing.T) {
	if err := (shauthConfig{}).validate(); err != nil {
		t.Fatalf("disabled config: %v", err)
	}
	if err := (shauthConfig{issuer: "https://auth.dev.e6qu.dev", clientID: "id"}).validate(); err == nil {
		t.Fatal("partial config was accepted")
	}
	if err := (shauthConfig{issuer: "http://auth.dev.e6qu.dev", clientID: "id", clientSecret: "secret", publicURL: "https://bleeplab.dev.e6qu.dev"}).validate(); err == nil {
		t.Fatal("non-HTTPS issuer was accepted")
	}
	if err := (shauthConfig{issuer: "https://auth.dev.e6qu.dev", clientID: "id", clientSecret: "secret", publicURL: "https://bleeplab.dev.e6qu.dev", postLogoutURL: "http://auth.dev.e6qu.dev/apps"}).validate(); err == nil {
		t.Fatal("non-HTTPS post-logout URL was accepted")
	}
}

func TestSHAUTHLogoutClearsLocalSessionAndReturnsToConfiguredPortal(t *testing.T) {
	t.Setenv("BLEEPLAB_SHAUTH_ISSUER", "https://auth.dev.e6qu.dev")
	t.Setenv("BLEEPLAB_SHAUTH_CLIENT_ID", "client")
	t.Setenv("BLEEPLAB_SHAUTH_CLIENT_SECRET", "secret")
	t.Setenv("BLEEPLAB_PUBLIC_URL", "https://bleeplab.dev.e6qu.dev")
	t.Setenv("BLEEPLAB_SHAUTH_POST_LOGOUT_URL", "https://auth.dev.e6qu.dev/apps")
	s := NewServer(":0", zerolog.Nop())
	request := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusFound || response.Header().Get("Location") != "https://auth.dev.e6qu.dev/apps" {
		t.Fatalf("logout = %d %q", response.Code, response.Header().Get("Location"))
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != shauthSessionCookie || cookies[0].MaxAge >= 0 {
		t.Fatalf("logout cookie = %#v", cookies)
	}
}

func TestSHAUTHSignedSessionGuardsHumanSurfaceOnly(t *testing.T) {
	t.Setenv("BLEEPLAB_SHAUTH_ISSUER", "https://auth.dev.e6qu.dev")
	t.Setenv("BLEEPLAB_SHAUTH_CLIENT_ID", "client")
	t.Setenv("BLEEPLAB_SHAUTH_CLIENT_SECRET", "secret")
	t.Setenv("BLEEPLAB_PUBLIC_URL", "https://bleeplab.dev.e6qu.dev")
	s := NewServer(":0", zerolog.Nop())
	h := s.Handler()
	request := httptest.NewRequest(http.MethodGet, "/internal/status", nil)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusFound || response.Header().Get("Location") != "/auth/shauth" {
		t.Fatalf("human surface = %d %q, want redirect", response.Code, response.Header().Get("Location"))
	}
	request = httptest.NewRequest(http.MethodGet, "/health", nil)
	response = httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("health = %d, want 200", response.Code)
	}
	value, err := s.shauth.sign(shauthSession{Subject: "subject", Role: "developer", Expires: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatalf("sign session: %v", err)
	}
	request = httptest.NewRequest(http.MethodGet, "/internal/status", nil)
	request.AddCookie(&http.Cookie{Name: shauthSessionCookie, Value: value})
	response = httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("authenticated human surface = %d, want 200", response.Code)
	}
}

func TestSHAUTHSessionSurfaceIncludesUserIdentity(t *testing.T) {
	t.Setenv("BLEEPLAB_SHAUTH_ISSUER", "https://auth.dev.e6qu.dev")
	t.Setenv("BLEEPLAB_SHAUTH_CLIENT_ID", "client")
	t.Setenv("BLEEPLAB_SHAUTH_CLIENT_SECRET", "secret")
	t.Setenv("BLEEPLAB_PUBLIC_URL", "https://bleeplab.dev.e6qu.dev")
	s := NewServer(":0", zerolog.Nop())
	value, err := s.shauth.sign(shauthSession{
		Subject: "subject",
		Name:    "octocat",
		Email:   "octocat@example.com",
		Picture: "https://avatars.example.com/octocat.png",
		Role:    "developer",
		Expires: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("sign session: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/internal/session", nil)
	request.AddCookie(&http.Cookie{Name: shauthSessionCookie, Value: value})
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("session = %d, want 200", response.Code)
	}
	for _, field := range []string{`"name":"octocat"`, `"email":"octocat@example.com"`, `"picture":"https://avatars.example.com/octocat.png"`, `"role":"developer"`} {
		if !strings.Contains(response.Body.String(), field) {
			t.Fatalf("session body %q omitted %s", response.Body.String(), field)
		}
	}
}

package bleeplab

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func configureSHAUTHTest(t *testing.T, issuer string) {
	t.Helper()
	t.Setenv("BLEEPLAB_SHAUTH_ISSUER", issuer)
	t.Setenv("BLEEPLAB_SHAUTH_CLIENT_ID", "client")
	t.Setenv("BLEEPLAB_SHAUTH_CLIENT_SECRET", "secret")
	t.Setenv("BLEEPLAB_PUBLIC_URL", "https://bleeplab.dev.e6qu.dev")
	t.Setenv("BLEEPLAB_SHAUTH_STATE_DIR", t.TempDir())
}

func createTestSession(t *testing.T, s *Server, overrides ...func(*shauthSession)) string {
	t.Helper()
	session := shauthSession{
		Issuer: s.shauth.issuer, ClientID: s.shauth.clientID, Subject: "subject-1", SID: "sid-1", IDToken: "signed.id.token",
		Name: "octocat", Email: "octocat@example.com", EmailVerified: true, Picture: "https://avatars.example.com/octocat.png",
		Role: "developer", Created: time.Now().UTC(), Expires: time.Now().Add(time.Hour),
	}
	for _, override := range overrides {
		override(&session)
	}
	id, err := s.createSHAUTHSession(session)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func testSessionExists(t *testing.T, s *Server, id string) (shauthSession, bool) {
	t.Helper()
	session, ok, err := s.shauthState.session(id, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return session, ok
}

func TestSHAUTHConfigRequiresCompleteSecureCoordinates(t *testing.T) {
	if err := (shauthConfig{}).validate(); err != nil {
		t.Fatalf("disabled config: %v", err)
	}
	if err := (shauthConfig{issuer: "https://auth.dev.e6qu.dev", clientID: "id"}).validate(); err == nil {
		t.Fatal("partial config was accepted")
	}
	if err := (shauthConfig{issuer: "http://auth.dev.e6qu.dev", clientID: "id", clientSecret: "secret", publicURL: "https://bleeplab.dev.e6qu.dev", stateDir: "/state"}).validate(); err == nil {
		t.Fatal("non-HTTPS public issuer was accepted")
	}
	if err := (shauthConfig{issuer: "https://auth.dev.e6qu.dev", clientID: "id", clientSecret: "secret", publicURL: "https://bleeplab.dev.e6qu.dev/untrusted", stateDir: "/state"}).validate(); err == nil {
		t.Fatal("public URL containing a path was accepted")
	}
	config := shauthConfig{issuer: "https://auth.dev.e6qu.dev", clientID: "id", clientSecret: "secret", publicURL: "https://bleeplab.dev.e6qu.dev", stateDir: "/state"}
	if err := config.validate(); err != nil {
		t.Fatalf("complete config: %v", err)
	}
	if got := config.signedOutURL(); got != "https://bleeplab.dev.e6qu.dev/auth/signed-out" {
		t.Fatalf("same-origin signed-out URL = %q", got)
	}
	if got := config.logoutBridgeURL(); got != "https://bleeplab.dev.e6qu.dev/auth/shauth/logout/complete" {
		t.Fatalf("same-origin logout bridge URL = %q", got)
	}
	if got, err := config.providerLogoutCompletionURL(); err != nil || got != "https://auth.dev.e6qu.dev/oauth/logout/complete" {
		t.Fatalf("provider logout completion URL = %q, %v", got, err)
	}
	loopback := shauthConfig{issuer: "http://localhost:4444", clientID: "id", clientSecret: "secret", publicURL: "http://bleeplab.localhost:8929", stateDir: "/state", allowInsecure: true}
	if err := loopback.validate(); err != nil {
		t.Fatalf("explicit loopback development coordinates: %v", err)
	}
	loopback.issuer = "http://auth.example.test"
	if err := loopback.validate(); err == nil {
		t.Fatal("non-loopback insecure issuer was accepted")
	}
}

func TestSHAUTHLogoutBridgeIgnoresInputAndRedirectsOnlyToIssuerCompletion(t *testing.T) {
	configureSHAUTHTest(t, "https://auth.dev.e6qu.dev/tenant/")
	s := NewServer(":0", zerolog.Nop())

	for _, target := range []string{
		shauthLogoutBridgePath,
		shauthLogoutBridgePath + "?target=https%3A%2F%2Fattacker.example&state=attacker&token=secret",
		shauthLogoutBridgePath + "?post_logout_redirect_uri=https%3A%2F%2Fattacker.example",
	} {
		for attempt := 0; attempt < 2; attempt++ {
			request := httptest.NewRequest(http.MethodGet, target, nil)
			response := httptest.NewRecorder()
			s.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "https://auth.dev.e6qu.dev/oauth/logout/complete" {
				t.Fatalf("logout bridge %q replay %d = %d %q", target, attempt, response.Code, response.Header().Get("Location"))
			}
			if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Referrer-Policy") != "no-referrer" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("logout bridge security headers: cache=%q referrer=%q content-type-options=%q", response.Header().Get("Cache-Control"), response.Header().Get("Referrer-Policy"), response.Header().Get("X-Content-Type-Options"))
			}
		}
	}
}

func TestSHAUTHLogoutBridgeFailsClosedWithoutProvider(t *testing.T) {
	s := NewServer(":0", zerolog.Nop())
	request := httptest.NewRequest(http.MethodGet, shauthLogoutBridgePath+"?target=https%3A%2F%2Fattacker.example", nil)
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Location") != "" {
		t.Fatalf("unconfigured logout bridge = %d %q", response.Code, response.Header().Get("Location"))
	}
}

func TestSHAUTHConfigPreservesExactIssuer(t *testing.T) {
	t.Setenv("BLEEPLAB_SHAUTH_ISSUER", "https://auth.dev.e6qu.dev/tenant/")
	t.Setenv("BLEEPLAB_SHAUTH_CLIENT_ID", "client")
	t.Setenv("BLEEPLAB_SHAUTH_CLIENT_SECRET", "secret")
	t.Setenv("BLEEPLAB_PUBLIC_URL", "https://bleeplab.dev.e6qu.dev/")
	t.Setenv("BLEEPLAB_SHAUTH_STATE_DIR", t.TempDir())
	config := shauthConfigFromEnv()
	if config.issuer != "https://auth.dev.e6qu.dev/tenant/" {
		t.Fatalf("issuer was rewritten to %q", config.issuer)
	}
	if config.publicURL != "https://bleeplab.dev.e6qu.dev" {
		t.Fatalf("public origin = %q", config.publicURL)
	}
}

func TestSHAUTHLogoutClearsLocalStateBeforeProviderWork(t *testing.T) {
	configureSHAUTHTest(t, "https://auth.dev.e6qu.dev")
	s := NewServer(":0", zerolog.Nop())
	sessionID := createTestSession(t, s)
	request := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	request.AddCookie(&http.Cookie{Name: shauthSessionCookie, Value: sessionID})
	response := httptest.NewRecorder()
	session, ok, err := s.clearSHAUTHSessionForLogout(response, request)
	if err != nil || !ok || session.IDToken != "signed.id.token" {
		t.Fatalf("local logout = session %#v, ok=%t, err=%v", session, ok, err)
	}
	if _, exists := testSessionExists(t, s, sessionID); exists {
		t.Fatal("local session remained before provider logout")
	}
	cleared := map[string]bool{}
	for _, cookie := range response.Result().Cookies() {
		if cookie.MaxAge < 0 {
			cleared[cookie.Name] = true
		}
	}
	if !cleared[shauthSessionCookie] || !cleared[shauthTransactionCookie] {
		t.Fatalf("logout did not clear both browser cookies: %v", cleared)
	}
}

func TestSHAUTHFrontChannelLogoutRequiresExactIssuerAndSID(t *testing.T) {
	configureSHAUTHTest(t, "https://auth.dev.e6qu.dev")
	s := NewServer(":0", zerolog.Nop())
	revokedID := createTestSession(t, s)
	keptID := createTestSession(t, s, func(session *shauthSession) { session.SID = "sid-2" })

	request := httptest.NewRequest(http.MethodGet, "/auth/shauth/frontchannel-logout?iss=https%3A%2F%2Fattacker.example&sid=sid-1", nil)
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("untrusted front-channel response = %d", response.Code)
	}
	if _, exists := testSessionExists(t, s, revokedID); !exists {
		t.Fatal("untrusted issuer revoked a session")
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == shauthSessionCookie && cookie.MaxAge < 0 {
			t.Fatal("untrusted issuer cleared the browser session cookie")
		}
	}

	request = httptest.NewRequest(http.MethodGet, "/auth/shauth/frontchannel-logout?iss=https%3A%2F%2Fauth.dev.e6qu.dev&sid=sid-1", nil)
	request.AddCookie(&http.Cookie{Name: shauthSessionCookie, Value: keptID})
	response = httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("trusted front-channel response = %d, cache=%q", response.Code, response.Header().Get("Cache-Control"))
	}
	_, revokedExists := testSessionExists(t, s, revokedID)
	_, keptExists := testSessionExists(t, s, keptID)
	if revokedExists || !keptExists {
		t.Fatalf("front-channel revocation: revoked=%t kept=%t", revokedExists, keptExists)
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == shauthSessionCookie && cookie.MaxAge < 0 {
			t.Fatal("front-channel logout for another sid cleared the browser session")
		}
	}

	request = httptest.NewRequest(http.MethodGet, "/auth/shauth/frontchannel-logout?iss=https%3A%2F%2Fauth.dev.e6qu.dev&sid=sid-2", nil)
	request.AddCookie(&http.Cookie{Name: shauthSessionCookie, Value: keptID})
	response = httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if _, keptExists = testSessionExists(t, s, keptID); keptExists {
		t.Fatal("front-channel logout retained the matching browser session")
	}
	cleared := false
	for _, cookie := range response.Result().Cookies() {
		cleared = cleared || (cookie.Name == shauthSessionCookie && cookie.MaxAge < 0)
	}
	if !cleared {
		t.Fatal("front-channel logout did not clear its matching browser cookie")
	}
}

func TestSHAUTHSignedOutClearsLocalStateWithoutStartingLogin(t *testing.T) {
	configureSHAUTHTest(t, "https://auth.dev.e6qu.dev")
	s := NewServer(":0", zerolog.Nop())
	sessionID := createTestSession(t, s)
	request := httptest.NewRequest(http.MethodGet, "/auth/signed-out", nil)
	request.AddCookie(&http.Cookie{Name: shauthSessionCookie, Value: sessionID})
	request.AddCookie(&http.Cookie{Name: shauthTransactionCookie, Value: "stale-transaction"})
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Location") != "" {
		t.Fatalf("signed-out landing = %d location %q: %s", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `aria-label="Bleeplab">Bleeplab</span>`) ||
		!strings.Contains(response.Body.String(), `<h1 id="signed-out-title">You are signed out</h1>`) ||
		!strings.Contains(response.Body.String(), `href="/auth/shauth?return_to=%2Fui%2F">Sign in with Shauth</a>`) {
		t.Fatalf("signed-out landing did not render explicit login UI: %s", response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" || strings.Contains(response.Header().Get("Content-Security-Policy"), "unsafe-inline") {
		t.Fatalf("signed-out landing security headers: cache=%q CSP=%q", response.Header().Get("Cache-Control"), response.Header().Get("Content-Security-Policy"))
	}
	if _, exists := testSessionExists(t, s, sessionID); exists {
		t.Fatal("signed-out landing retained the local session")
	}

	request = httptest.NewRequest(http.MethodGet, "/auth/signed-out.css", nil)
	response = httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "text/css; charset=utf-8" {
		t.Fatalf("signed-out stylesheet = %d content-type %q", response.Code, response.Header().Get("Content-Type"))
	}
	for _, contract := range []string{"prefers-color-scheme: dark", ".primary-action:focus-visible", "prefers-reduced-motion: no-preference"} {
		if !strings.Contains(response.Body.String(), contract) {
			t.Fatalf("signed-out stylesheet omitted %q", contract)
		}
	}
}

func TestSHAUTHValidationRequiresRealSessionCookieAndReportsExactContract(t *testing.T) {
	configureSHAUTHTest(t, "https://auth.dev.e6qu.dev")
	t.Setenv("APPLICATION_RELEASE_REVISION", "sha256:"+strings.Repeat("a", 64))
	s := NewServer(":0", zerolog.Nop())

	for name, configure := range map[string]func(*http.Request){
		"anonymous": func(*http.Request) {},
		"basic": func(request *http.Request) {
			request.SetBasicAuth("shauth-validator", "not-an-application-credential")
		},
		"bearer": func(request *http.Request) {
			request.Header.Set("Authorization", "Bearer not-an-application-credential")
		},
		"query": func(request *http.Request) {
			request.URL.RawQuery = "token=not-an-application-credential&username=shauth-validator"
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/auth/validation", nil)
			configure(request)
			response := httptest.NewRecorder()
			s.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/auth/signed-out" {
				t.Fatalf("credential-shaped request = %d %q, want app-local signed-out redirect", response.Code, response.Header().Get("Location"))
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("credential-shaped response cache policy = %q", response.Header().Get("Cache-Control"))
			}
		})
	}

	sessionID := createTestSession(t, s, func(session *shauthSession) {
		session.Name = `ada<script>`
		session.Email = `ada+validation@example.com`
		session.Role = "admin"
	})
	request := httptest.NewRequest(http.MethodGet, "/auth/validation", nil)
	request.AddCookie(&http.Cookie{Name: shauthSessionCookie, Value: sessionID})
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("authenticated validation = %d: %s", response.Code, response.Body.String())
	}
	for _, contract := range []string{
		`<main class="auth-shell" id="main-content">`,
		`<span class="brand" aria-label="Bleeplab">Bleeplab</span>`,
		`data-testid="validation-username">ada&lt;script&gt;</dd>`,
		`data-testid="validation-email">ada&#43;validation@example.com</dd>`,
		`data-testid="validation-role">admin</dd>`,
		`data-testid="validation-release">sha256:` + strings.Repeat("a", 64) + `</dd>`,
		`<form action="/auth/logout" method="post">`,
		`<button class="primary-action" type="submit">Sign out</button>`,
	} {
		if !strings.Contains(response.Body.String(), contract) {
			t.Fatalf("validation page omitted %q: %s", contract, response.Body.String())
		}
	}
	if strings.Contains(response.Body.String(), `<script>`) ||
		response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("Referrer-Policy") != "same-origin" ||
		response.Header().Get("Content-Security-Policy") != "default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'self' https://auth.dev.e6qu.dev; frame-ancestors 'none'" {
		t.Fatalf("validation response did not enforce output/security contract: cache=%q referrer=%q CSP=%q body=%s", response.Header().Get("Cache-Control"), response.Header().Get("Referrer-Policy"), response.Header().Get("Content-Security-Policy"), response.Body.String())
	}
}

func TestSHAUTHValidationWithoutProviderStillFailsClosedLocally(t *testing.T) {
	s := NewServer(":0", zerolog.Nop())
	request := httptest.NewRequest(http.MethodGet, "/auth/validation", nil)
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/auth/signed-out" {
		t.Fatalf("standalone validation = %d %q", response.Code, response.Header().Get("Location"))
	}
}

func TestSHAUTHLogoutRequiresExactSameOriginNavigation(t *testing.T) {
	config := shauthConfig{publicURL: "https://bleeplab.dev.e6qu.dev"}
	valid := []http.Header{
		{"Origin": {config.publicURL}},
		{
			"Origin":         {config.publicURL},
			"Sec-Fetch-Site": {"same-origin"},
			"Sec-Fetch-Mode": {"navigate"},
			"Sec-Fetch-Dest": {"document"},
		},
	}
	for index, headers := range valid {
		request := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
		request.Header = headers
		if !config.validLogoutRequest(request) {
			t.Errorf("valid same-origin logout request %d was rejected", index)
		}
	}

	invalid := map[string]http.Header{
		"missing origin": {},
		"opaque origin": {
			"Origin":         {"null"},
			"Sec-Fetch-Site": {"same-origin"},
			"Sec-Fetch-Mode": {"navigate"},
			"Sec-Fetch-Dest": {"document"},
		},
		"cross origin": {
			"Origin": {"https://attacker.example"},
		},
		"cross site": {
			"Origin":         {config.publicURL},
			"Sec-Fetch-Site": {"cross-site"},
		},
		"same site is not same origin": {
			"Origin":         {config.publicURL},
			"Sec-Fetch-Site": {"same-site"},
		},
		"browser initiated top-level request without an application document": {
			"Origin":         {config.publicURL},
			"Sec-Fetch-Site": {"none"},
		},
		"non-navigation mode": {
			"Origin":         {config.publicURL},
			"Sec-Fetch-Site": {"same-origin"},
			"Sec-Fetch-Mode": {"cors"},
		},
		"non-document destination": {
			"Origin":         {config.publicURL},
			"Sec-Fetch-Site": {"same-origin"},
			"Sec-Fetch-Mode": {"navigate"},
			"Sec-Fetch-Dest": {"iframe"},
		},
	}
	for name, headers := range invalid {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
			request.Header = headers
			if config.validLogoutRequest(request) {
				t.Fatal("untrusted logout request was accepted")
			}
		})
	}
}

func TestSHAUTHLogoutEndpointRequiresExactIssuerOrigin(t *testing.T) {
	config := shauthConfig{issuer: "https://auth.dev.e6qu.dev", clientID: "bleeplab-dev", publicURL: "https://bleeplab.dev.e6qu.dev", allowInsecure: false}
	endpoint, err := config.logoutEndpoint("https://auth.dev.e6qu.dev/oauth2/sessions/logout")
	if err != nil || endpoint.String() != "https://auth.dev.e6qu.dev/oauth2/sessions/logout" {
		t.Fatalf("valid logout endpoint = %v, %v", endpoint, err)
	}
	for _, value := range []string{"https://attacker.example/logout", "http://auth.dev.e6qu.dev/logout", "https://user@auth.dev.e6qu.dev/logout", "https://auth.dev.e6qu.dev/logout#fragment"} {
		if _, err := config.logoutEndpoint(value); err == nil {
			t.Errorf("untrusted logout endpoint %q was accepted", value)
		}
	}
	if got := config.validationContentSecurityPolicy(); got != "default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'self' https://auth.dev.e6qu.dev; frame-ancestors 'none'" {
		t.Fatalf("validation CSP = %q", got)
	}
	endpoint, err = config.rpInitiatedLogoutURL("https://auth.dev.e6qu.dev/oauth2/sessions/logout?id_token_hint=attacker&client_id=attacker&post_logout_redirect_uri=https%3A%2F%2Fattacker.example", "verified.id.token")
	if err != nil {
		t.Fatal(err)
	}
	query := endpoint.Query()
	if endpoint.Scheme != "https" || endpoint.Host != "auth.dev.e6qu.dev" || endpoint.Path != "/oauth2/sessions/logout" ||
		query.Get("id_token_hint") != "verified.id.token" || query.Get("client_id") != "bleeplab-dev" || query.Get("post_logout_redirect_uri") != "https://bleeplab.dev.e6qu.dev/auth/shauth/logout/complete" {
		t.Fatalf("RP-Initiated Logout endpoint = %q", endpoint.String())
	}
	withoutSession, err := config.rpInitiatedLogoutURL("https://auth.dev.e6qu.dev/oauth2/sessions/logout?id_token_hint=attacker", "")
	if err != nil {
		t.Fatal(err)
	}
	if withoutSession.Query().Has("id_token_hint") || withoutSession.Query().Get("client_id") != "bleeplab-dev" || withoutSession.Query().Get("post_logout_redirect_uri") != config.logoutBridgeURL() {
		t.Fatalf("sessionless RP-Initiated Logout endpoint = %q", withoutSession.String())
	}
}

func TestSHAUTHBackChannelRejectsMalformedRequestsWithoutProviderWork(t *testing.T) {
	configureSHAUTHTest(t, "https://auth.dev.e6qu.dev")
	s := NewServer(":0", zerolog.Nop())
	for name, contentType := range map[string]string{
		"wrong content type": "application/json",
		"missing token":      "application/x-www-form-urlencoded",
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/auth/shauth/backchannel-logout", nil)
			request.Header.Set("Content-Type", contentType)
			response := httptest.NewRecorder()
			s.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("malformed logout request = %d cache %q", response.Code, response.Header().Get("Cache-Control"))
			}
		})
	}
}

func TestSHAUTHSessionGuardsHumanSurfaceAndIncludesVerifiedIdentity(t *testing.T) {
	configureSHAUTHTest(t, "https://auth.dev.e6qu.dev")
	s := NewServer(":0", zerolog.Nop())
	handler := s.Handler()
	request := httptest.NewRequest(http.MethodGet, "/internal/status?view=full", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusFound || response.Header().Get("Location") != "/auth/shauth?return_to=%2Fui%2F" {
		t.Fatalf("human surface = %d %q, want Shauth redirect to an allowlisted UI return", response.Code, response.Header().Get("Location"))
	}
	request = httptest.NewRequest(http.MethodGet, "/health", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("health = %d, want 200", response.Code)
	}
	sessionID := createTestSession(t, s)
	request = httptest.NewRequest(http.MethodGet, "/internal/session", nil)
	request.AddCookie(&http.Cookie{Name: shauthSessionCookie, Value: sessionID})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("session = %d, want 200", response.Code)
	}
	for _, field := range []string{`"name":"octocat"`, `"email":"octocat@example.com"`, `"picture":"https://avatars.example.com/octocat.png"`, `"role":"developer"`} {
		if !strings.Contains(response.Body.String(), field) {
			t.Fatalf("session body %q omitted %s", response.Body.String(), field)
		}
	}
	unverifiedID := createTestSession(t, s, func(session *shauthSession) { session.EmailVerified = false })
	request = httptest.NewRequest(http.MethodGet, "/ui/", nil)
	request.AddCookie(&http.Cookie{Name: shauthSessionCookie, Value: unverifiedID})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusFound || response.Header().Get("Location") != "/auth/shauth?return_to=%2Fui%2F" {
		t.Fatalf("unverified session did not fail closed: %d %q", response.Code, response.Header().Get("Location"))
	}
}

func TestSHAUTHSessionStateFailureIsFailClosed(t *testing.T) {
	configureSHAUTHTest(t, "https://auth.dev.e6qu.dev")
	s := NewServer(":0", zerolog.Nop())
	sessionID := createTestSession(t, s)
	path := filepath.Join(s.shauthState.sessionsDir, sessionID+".json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	request.AddCookie(&http.Cookie{Name: shauthSessionCookie, Value: sessionID})
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("corrupt durable session state = %d, want 503 fail-closed", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/auth/signed-out", nil)
	request.AddCookie(&http.Cookie{Name: shauthSessionCookie, Value: sessionID})
	response = httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Location") != "" {
		t.Fatalf("signed-out recovery from corrupt state = %d %q", response.Code, response.Header().Get("Location"))
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("signed-out recovery retained corrupt session state: %v", err)
	}
}

func TestSafeReturnToAllowsOnlyBleeplabUI(t *testing.T) {
	for _, value := range []string{"https://attacker.example", "//attacker.example/path", `/\attacker.example/path`, "/%5Cattacker.example/path", "/%2F%2Fattacker.example/path", "not-a-path", "", "/internal/status", "/auth/logout", "/api/v4/projects"} {
		if got := safeReturnTo(value); got != "/ui/" {
			t.Errorf("safeReturnTo(%q) = %q", value, got)
		}
	}
	if got := safeReturnTo("/ui/projects/7?tab=pipelines"); got != "/ui/projects/7?tab=pipelines" {
		t.Fatalf("local UI return path = %q", got)
	}
}

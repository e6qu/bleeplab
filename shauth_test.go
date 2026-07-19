package bleeplab

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/rs/zerolog"
)

type oidcTestProvider struct {
	server         *httptest.Server
	signer         jose.Signer
	key            jose.JSONWebKey
	issuer         string
	logoutEndpoint string
	nonce          string
	omitSID        bool
}

func newOIDCTestProvider(t *testing.T) *oidcTestProvider {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"))
	if err != nil {
		t.Fatal(err)
	}
	p := &oidcTestProvider{signer: signer, key: jose.JSONWebKey{Key: &privateKey.PublicKey, KeyID: "test-key", Algorithm: string(jose.RS256), Use: "sig"}, nonce: "expected-nonce"}
	p.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(w, http.StatusOK, map[string]any{
				"issuer": p.issuer, "authorization_endpoint": p.server.URL + "/authorize",
				"token_endpoint": p.server.URL + "/token", "jwks_uri": p.server.URL + "/jwks",
				"end_session_endpoint": p.logoutEndpoint,
			})
		case "/jwks":
			writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{p.key}})
		case "/token":
			if err := r.ParseForm(); err != nil || r.PostForm.Get("code") == "" || r.PostForm.Get("code_verifier") == "" {
				http.Error(w, "invalid token request", http.StatusBadRequest)
				return
			}
			claims := map[string]any{
				"iss": p.issuer, "aud": "client", "sub": "subject-1",
				"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "nonce": p.nonce,
				"preferred_username": "octocat", "email": "octocat@example.com", "picture": "https://avatars.example.com/octocat.png", "role": "developer",
			}
			if !p.omitSID {
				claims["sid"] = "sid-1"
			}
			raw := p.sign(t, claims)
			writeJSON(w, http.StatusOK, map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600, "id_token": raw})
		default:
			http.NotFound(w, r)
		}
	}))
	p.issuer = p.server.URL
	p.logoutEndpoint = p.server.URL + "/logout"
	t.Cleanup(p.server.Close)
	return p
}

func (p *oidcTestProvider) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	raw, err := jwt.Signed(p.signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (p *oidcTestProvider) request(t *testing.T, method, target string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, target, nil)
	return r.WithContext(oidc.ClientContext(r.Context(), p.server.Client()))
}

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
		Name: "octocat", Email: "octocat@example.com", Picture: "https://avatars.example.com/octocat.png",
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

func TestSHAUTHConfigRequiresCompleteHTTPSCoordinates(t *testing.T) {
	if err := (shauthConfig{}).validate(); err != nil {
		t.Fatalf("disabled config: %v", err)
	}
	if err := (shauthConfig{issuer: "https://auth.dev.e6qu.dev", clientID: "id"}).validate(); err == nil {
		t.Fatal("partial config was accepted")
	}
	if err := (shauthConfig{issuer: "http://auth.dev.e6qu.dev", clientID: "id", clientSecret: "secret", publicURL: "https://bleeplab.dev.e6qu.dev", stateDir: "/state"}).validate(); err == nil {
		t.Fatal("non-HTTPS issuer was accepted")
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

func TestSHAUTHCallbackVerifiesIdentityAndStoresTokenServerSide(t *testing.T) {
	provider := newOIDCTestProvider(t)
	configureSHAUTHTest(t, provider.server.URL)
	s := NewServer(":0", zerolog.Nop())
	tx, err := s.shauth.sign(shauthTransaction{State: "state", Nonce: provider.nonce, Verifier: "verifier", ReturnTo: "/ui/projects/7", Expires: time.Now().Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	request := provider.request(t, http.MethodGet, "/auth/shauth/callback?code=code&state=state")
	request.AddCookie(&http.Cookie{Name: shauthTransactionCookie, Value: tx})
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusFound || response.Header().Get("Location") != "/ui/projects/7" {
		t.Fatalf("callback = %d %q: %s", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == shauthSessionCookie && cookie.MaxAge > 0 {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil || strings.Contains(sessionCookie.Value, ".") {
		t.Fatalf("browser did not receive an opaque session identifier: %#v", sessionCookie)
	}
	session, ok := testSessionExists(t, s, sessionCookie.Value)
	if !ok || session.Issuer != provider.server.URL || session.Subject != "subject-1" || session.SID != "sid-1" || session.IDToken == "" {
		t.Fatalf("verified server-side session = %#v", session)
	}
}

func TestSHAUTHCallbackAcceptsIDTokenWithoutOptionalSID(t *testing.T) {
	provider := newOIDCTestProvider(t)
	provider.omitSID = true
	provider.issuer += "/"
	configureSHAUTHTest(t, provider.issuer)
	s := NewServer(":0", zerolog.Nop())
	tx, err := s.shauth.sign(shauthTransaction{State: "state", Nonce: provider.nonce, Verifier: "verifier", ReturnTo: "/ui/", Expires: time.Now().Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	request := provider.request(t, http.MethodGet, "/auth/shauth/callback?code=code&state=state")
	request.AddCookie(&http.Cookie{Name: shauthTransactionCookie, Value: tx})
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusFound {
		t.Fatalf("callback without sid = %d: %s", response.Code, response.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == shauthSessionCookie && cookie.MaxAge > 0 {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil {
		t.Fatal("callback did not create a session cookie")
	}
	session, exists := testSessionExists(t, s, sessionCookie.Value)
	if !exists || session.Issuer != provider.issuer || session.SID != "" {
		t.Fatalf("session from trailing-slash issuer without sid = %#v, exists=%t", session, exists)
	}
}

func TestSHAUTHLoginUsesDiscoveryPKCEStateNonceAndReturnPath(t *testing.T) {
	provider := newOIDCTestProvider(t)
	configureSHAUTHTest(t, provider.server.URL)
	s := NewServer(":0", zerolog.Nop())
	request := provider.request(t, http.MethodGet, "/auth/shauth?return_to=%2Fui%2Fprojects%2F7%3Ftab%3Djobs")
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusFound {
		t.Fatalf("login = %d: %s", response.Code, response.Body.String())
	}
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.String() == "" || location.Path != "/authorize" {
		t.Fatalf("authorization location = %q (%v)", response.Header().Get("Location"), err)
	}
	query := location.Query()
	for _, key := range []string{"state", "nonce", "code_challenge"} {
		if query.Get(key) == "" {
			t.Fatalf("authorization query omitted %s: %v", key, query)
		}
	}
	if query.Get("code_challenge_method") != "S256" || query.Get("redirect_uri") != "https://bleeplab.dev.e6qu.dev/auth/shauth/callback" {
		t.Fatalf("authorization query = %v", query)
	}
	var transactionCookie *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == shauthTransactionCookie {
			transactionCookie = cookie
		}
	}
	if transactionCookie == nil {
		t.Fatal("transaction cookie is missing")
	}
	var transaction shauthTransaction
	if err := s.shauth.verify(transactionCookie.Value, &transaction); err != nil || transaction.ReturnTo != "/ui/projects/7?tab=jobs" {
		t.Fatalf("transaction = %#v (%v)", transaction, err)
	}
}

func TestSHAUTHLogoutClearsLocalSessionAndInitiatesProviderLogout(t *testing.T) {
	provider := newOIDCTestProvider(t)
	configureSHAUTHTest(t, provider.server.URL)
	s := NewServer(":0", zerolog.Nop())
	sessionID := createTestSession(t, s)
	request := provider.request(t, http.MethodPost, "/auth/logout")
	request.Header.Set("Origin", "https://bleeplab.dev.e6qu.dev")
	request.AddCookie(&http.Cookie{Name: shauthSessionCookie, Value: sessionID})
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusFound {
		t.Fatalf("logout = %d: %s", response.Code, response.Body.String())
	}
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.String() == "" || location.Path != "/logout" {
		t.Fatalf("logout location = %q (%v)", response.Header().Get("Location"), err)
	}
	if location.Query().Get("id_token_hint") != "signed.id.token" || location.Query().Get("post_logout_redirect_uri") != "https://bleeplab.dev.e6qu.dev/auth/signed-out" {
		t.Fatalf("logout query = %v", location.Query())
	}
	_, exists := testSessionExists(t, s, sessionID)
	if exists {
		t.Fatal("local session remained after logout")
	}
}

func TestSHAUTHLogoutRejectsProviderEndpointOutsideIssuerOriginWithoutClearingSession(t *testing.T) {
	provider := newOIDCTestProvider(t)
	provider.logoutEndpoint = "https://attacker.example/logout"
	configureSHAUTHTest(t, provider.issuer)
	s := NewServer(":0", zerolog.Nop())
	sessionID := createTestSession(t, s)
	request := provider.request(t, http.MethodPost, "/auth/logout")
	request.Header.Set("Origin", "https://bleeplab.dev.e6qu.dev")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.AddCookie(&http.Cookie{Name: shauthSessionCookie, Value: sessionID})
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("wrong-origin provider logout = %d: %s", response.Code, response.Body.String())
	}
	if _, exists := testSessionExists(t, s, sessionID); !exists {
		t.Fatal("local session was cleared before provider logout coordinates were validated")
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == shauthSessionCookie && cookie.MaxAge < 0 {
			t.Fatal("session cookie was cleared on failed provider logout")
		}
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
	if response.Code != http.StatusOK {
		t.Fatalf("signed-out landing = %d: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Location") != "" {
		t.Fatalf("signed-out landing initiated login at %q", response.Header().Get("Location"))
	}
	if !strings.Contains(response.Body.String(), "You are signed out") || !strings.Contains(response.Body.String(), `href="/auth/shauth?return_to=%2Fui%2F"`) {
		t.Fatalf("signed-out landing did not render explicit login UI: %s", response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("signed-out landing cache control = %q", response.Header().Get("Cache-Control"))
	}
	_, exists := testSessionExists(t, s, sessionID)
	if exists {
		t.Fatal("signed-out landing retained the local session")
	}
	cleared := map[string]bool{}
	for _, cookie := range response.Result().Cookies() {
		if cookie.MaxAge < 0 {
			cleared[cookie.Name] = true
		}
	}
	if !cleared[shauthSessionCookie] || !cleared[shauthTransactionCookie] {
		t.Fatalf("signed-out landing did not clear authentication cookies: %v", cleared)
	}
}

func TestSHAUTHLogoutRejectsCrossOriginPost(t *testing.T) {
	configureSHAUTHTest(t, "https://auth.dev.e6qu.dev")
	s := NewServer(":0", zerolog.Nop())
	request := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	request.Header.Set("Origin", "https://attacker.example")
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-origin logout = %d, want 403", response.Code)
	}
}

func TestSHAUTHBackChannelLogoutVerifiesAndRevokesSID(t *testing.T) {
	provider := newOIDCTestProvider(t)
	configureSHAUTHTest(t, provider.server.URL)
	s := NewServer(":0", zerolog.Nop())
	revokedID := createTestSession(t, s)
	keptID := createTestSession(t, s, func(session *shauthSession) { session.SID = "sid-2" })
	logoutToken := provider.sign(t, map[string]any{
		"iss": provider.server.URL, "aud": "client", "sub": "subject-1", "sid": "sid-1",
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(), "jti": "logout-1",
		"events": map[string]any{backChannelLogoutEvent: map[string]any{}},
	})
	form := url.Values{"logout_token": {logoutToken}}
	request := httptest.NewRequest(http.MethodPost, "/auth/shauth/backchannel-logout", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request = request.WithContext(oidc.ClientContext(context.Background(), provider.server.Client()))
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("back-channel logout = %d: %s", response.Code, response.Body.String())
	}
	_, revokedExists := testSessionExists(t, s, revokedID)
	_, keptExists := testSessionExists(t, s, keptID)
	if revokedExists || !keptExists {
		t.Fatalf("session revocation: revoked exists=%t, unrelated exists=%t", revokedExists, keptExists)
	}

	replay := httptest.NewRequest(http.MethodPost, "/auth/shauth/backchannel-logout", strings.NewReader(form.Encode()))
	replay.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replay = replay.WithContext(oidc.ClientContext(context.Background(), provider.server.Client()))
	replayResponse := httptest.NewRecorder()
	s.Handler().ServeHTTP(replayResponse, replay)
	if replayResponse.Code != http.StatusBadRequest {
		t.Fatalf("logout token replay = %d, want 400", replayResponse.Code)
	}

	subjectSession1 := createTestSession(t, s, func(session *shauthSession) { session.SID = "sid-subject-1" })
	subjectSession2 := createTestSession(t, s, func(session *shauthSession) { session.SID = "sid-subject-2" })
	subjectToken := provider.sign(t, map[string]any{
		"iss": provider.server.URL, "aud": "client", "sub": "subject-1",
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(), "jti": "logout-subject",
		"events": map[string]any{backChannelLogoutEvent: map[string]any{}},
	})
	subjectForm := url.Values{"logout_token": {subjectToken}}
	subjectRequest := httptest.NewRequest(http.MethodPost, "/auth/shauth/backchannel-logout", strings.NewReader(subjectForm.Encode()))
	subjectRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	subjectRequest = subjectRequest.WithContext(oidc.ClientContext(context.Background(), provider.server.Client()))
	subjectResponse := httptest.NewRecorder()
	s.Handler().ServeHTTP(subjectResponse, subjectRequest)
	if subjectResponse.Code != http.StatusNoContent {
		t.Fatalf("subject back-channel logout = %d: %s", subjectResponse.Code, subjectResponse.Body.String())
	}
	_, subject1Exists := testSessionExists(t, s, subjectSession1)
	_, subject2Exists := testSessionExists(t, s, subjectSession2)
	if subject1Exists || subject2Exists {
		t.Fatalf("subject logout left sessions: first=%t second=%t", subject1Exists, subject2Exists)
	}
}

func TestSHAUTHBackChannelLogoutRejectsTamperedToken(t *testing.T) {
	provider := newOIDCTestProvider(t)
	configureSHAUTHTest(t, provider.server.URL)
	s := NewServer(":0", zerolog.Nop())
	token := provider.sign(t, map[string]any{
		"iss": provider.server.URL, "aud": "client", "sid": "sid-1",
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(), "jti": "tampered",
		"events": map[string]any{backChannelLogoutEvent: map[string]any{}},
	})
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(parts[2]) == 0 {
		t.Fatalf("signed token has unexpected shape")
	}
	replacement := "A"
	if strings.HasPrefix(parts[2], replacement) {
		replacement = "B"
	}
	parts[2] = replacement + parts[2][1:]
	token = strings.Join(parts, ".")
	form := url.Values{"logout_token": {token}}
	request := httptest.NewRequest(http.MethodPost, "/auth/shauth/backchannel-logout", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request = request.WithContext(oidc.ClientContext(context.Background(), provider.server.Client()))
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("tampered logout token = %d, want 400", response.Code)
	}
}

func TestSHAUTHBackChannelLogoutValidatesRequiredClaimsAndEventShape(t *testing.T) {
	provider := newOIDCTestProvider(t)
	configureSHAUTHTest(t, provider.issuer)
	s := NewServer(":0", zerolog.Nop())
	base := func(jti string) map[string]any {
		return map[string]any{
			"iss": provider.issuer, "aud": "client", "sid": "sid-1",
			"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(), "jti": jti,
			"events": map[string]any{backChannelLogoutEvent: map[string]any{}},
		}
	}
	request := func(claims map[string]any) int {
		token := provider.sign(t, claims)
		form := url.Values{"logout_token": {token}}
		r := httptest.NewRequest(http.MethodPost, "/auth/shauth/backchannel-logout", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r = r.WithContext(oidc.ClientContext(context.Background(), provider.server.Client()))
		response := httptest.NewRecorder()
		s.Handler().ServeHTTP(response, r)
		return response.Code
	}

	missingExpiry := base("missing-exp")
	delete(missingExpiry, "exp")
	if code := request(missingExpiry); code != http.StatusBadRequest {
		t.Fatalf("missing exp = %d, want 400", code)
	}
	for name, nonce := range map[string]any{"empty": "", "null": nil} {
		claims := base("nonce-" + name)
		claims["nonce"] = nonce
		if code := request(claims); code != http.StatusBadRequest {
			t.Fatalf("%s nonce = %d, want 400", name, code)
		}
	}
	badEvent := base("array-event")
	badEvent["events"] = map[string]any{backChannelLogoutEvent: []any{}}
	if code := request(badEvent); code != http.StatusBadRequest {
		t.Fatalf("array logout event = %d, want 400", code)
	}
	extraEvent := base("extra-event")
	extraEvent["events"] = map[string]any{backChannelLogoutEvent: map[string]any{}, "https://example.com/another-event": map[string]any{}}
	if code := request(extraEvent); code != http.StatusNoContent {
		t.Fatalf("valid logout token with extra event = %d, want 204", code)
	}
}

func TestSHAUTHBackChannelLogoutRevocationOutlivesLogoutToken(t *testing.T) {
	provider := newOIDCTestProvider(t)
	configureSHAUTHTest(t, provider.issuer)
	s := NewServer(":0", zerolog.Nop())
	sessionID := createTestSession(t, s)
	now := time.Now().UTC().Truncate(time.Second)
	logoutToken := provider.sign(t, map[string]any{
		"iss": provider.issuer, "aud": "client", "sid": "sid-1",
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": "short-token",
		"events": map[string]any{backChannelLogoutEvent: map[string]any{}},
	})
	form := url.Values{"logout_token": {logoutToken}}
	request := httptest.NewRequest(http.MethodPost, "/auth/shauth/backchannel-logout", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request = request.WithContext(oidc.ClientContext(context.Background(), provider.server.Client()))
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("back-channel logout = %d: %s", response.Code, response.Body.String())
	}
	if _, exists, err := s.shauthState.session(sessionID, now.Add(2*time.Minute)); err != nil || exists {
		t.Fatalf("session after logout token expiry: exists=%t err=%v", exists, err)
	}
}

func TestSHAUTHStateIsSharedAcrossServerRestartsAndReplicas(t *testing.T) {
	provider := newOIDCTestProvider(t)
	configureSHAUTHTest(t, provider.issuer)
	sharedState := t.TempDir()
	t.Setenv("BLEEPLAB_SHAUTH_STATE_DIR", sharedState)
	first := NewServer(":0", zerolog.Nop())
	sessionID := createTestSession(t, first)
	second := NewServer(":0", zerolog.Nop())
	if _, exists := testSessionExists(t, second, sessionID); !exists {
		t.Fatal("second replica could not read the first replica's session")
	}
	logoutToken := provider.sign(t, map[string]any{
		"iss": provider.issuer, "aud": "client", "sid": "sid-1",
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(), "jti": "shared-logout",
		"events": map[string]any{backChannelLogoutEvent: map[string]any{}},
	})
	form := url.Values{"logout_token": {logoutToken}}
	post := func(server *Server) int {
		request := httptest.NewRequest(http.MethodPost, "/auth/shauth/backchannel-logout", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request = request.WithContext(oidc.ClientContext(context.Background(), provider.server.Client()))
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response.Code
	}
	if code := post(second); code != http.StatusNoContent {
		t.Fatalf("replica logout = %d, want 204", code)
	}
	if _, exists := testSessionExists(t, first, sessionID); exists {
		t.Fatal("first replica accepted a session revoked by the second replica")
	}
	third := NewServer(":0", zerolog.Nop())
	if code := post(third); code != http.StatusBadRequest {
		t.Fatalf("replayed logout token after restart = %d, want 400", code)
	}
}

func TestSHAUTHSessionGuardsHumanSurfaceAndIncludesIdentity(t *testing.T) {
	configureSHAUTHTest(t, "https://auth.dev.e6qu.dev")
	s := NewServer(":0", zerolog.Nop())
	handler := s.Handler()
	request := httptest.NewRequest(http.MethodGet, "/internal/status?view=full", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusFound || response.Header().Get("Location") != "/auth/shauth?return_to=%2Finternal%2Fstatus%3Fview%3Dfull" {
		t.Fatalf("human surface = %d %q, want Shauth redirect", response.Code, response.Header().Get("Location"))
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
}

func TestSafeReturnToRejectsExternalDestinations(t *testing.T) {
	for _, value := range []string{"https://attacker.example", "//attacker.example/path", `/\attacker.example/path`, "/%5Cattacker.example/path", "/%2F%2Fattacker.example/path", "not-a-path", ""} {
		if got := safeReturnTo(value); got != "/ui/" {
			t.Errorf("safeReturnTo(%q) = %q", value, got)
		}
	}
	if got := safeReturnTo("/ui/projects/7?tab=pipelines"); got != "/ui/projects/7?tab=pipelines" {
		t.Fatalf("local return path = %q", got)
	}
}

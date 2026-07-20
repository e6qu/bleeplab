package bleeplab

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const shauthTransactionCookie = "bleeplab_shauth_tx"
const shauthSessionCookie = "bleeplab_shauth_session"
const backChannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"
const shauthMaximumSessionLifetime = 8 * time.Hour

//go:embed auth/signed-out.html
var shauthSignedOutHTML string

//go:embed auth/signed-out.css
var shauthSignedOutCSS string

type shauthConfig struct {
	issuer, clientID, clientSecret, publicURL, stateDir string
	allowInsecure                                       bool
}

func shauthConfigFromEnv() shauthConfig {
	return shauthConfig{
		issuer:        strings.TrimSpace(os.Getenv("BLEEPLAB_SHAUTH_ISSUER")),
		clientID:      strings.TrimSpace(os.Getenv("BLEEPLAB_SHAUTH_CLIENT_ID")),
		clientSecret:  strings.TrimSpace(os.Getenv("BLEEPLAB_SHAUTH_CLIENT_SECRET")),
		publicURL:     strings.TrimRight(strings.TrimSpace(os.Getenv("BLEEPLAB_PUBLIC_URL")), "/"),
		stateDir:      strings.TrimSpace(os.Getenv("BLEEPLAB_SHAUTH_STATE_DIR")),
		allowInsecure: os.Getenv("BLEEPLAB_ALLOW_INSECURE_OIDC") == "true",
	}
}

func (c shauthConfig) enabled() bool {
	return c.issuer != "" && c.clientID != "" && c.clientSecret != "" && c.publicURL != "" && c.stateDir != ""
}

func (c shauthConfig) validate() error {
	n := 0
	for _, v := range []string{c.issuer, c.clientID, c.clientSecret, c.publicURL, c.stateDir} {
		if v != "" {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	if n != 5 {
		return fmt.Errorf("BLEEPLAB_SHAUTH_ISSUER, BLEEPLAB_SHAUTH_CLIENT_ID, BLEEPLAB_SHAUTH_CLIENT_SECRET, BLEEPLAB_PUBLIC_URL, and BLEEPLAB_SHAUTH_STATE_DIR must be configured together")
	}
	issuer, err := url.Parse(c.issuer)
	if err != nil || !c.validOIDCURL(issuer) || issuer.RawQuery != "" || issuer.Fragment != "" {
		return fmt.Errorf("Shauth issuer must be an absolute secure URL")
	}
	publicURL, err := url.Parse(c.publicURL)
	if err != nil || !c.validOIDCURL(publicURL) || (publicURL.Path != "" && publicURL.Path != "/") || publicURL.RawQuery != "" || publicURL.Fragment != "" {
		return fmt.Errorf("Bleeplab public URL must be an absolute secure origin")
	}
	return nil
}

func (c shauthConfig) validOIDCURL(value *url.URL) bool {
	if value == nil || value.Host == "" || value.User != nil {
		return false
	}
	if value.Scheme == "https" {
		return true
	}
	host := strings.ToLower(value.Hostname())
	return c.allowInsecure && value.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1" || strings.HasSuffix(host, ".localhost"))
}

func (c shauthConfig) signedOutURL() string {
	return c.publicURL + "/auth/signed-out"
}

type shauthTransaction struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	ReturnTo string `json:"r"`
	Expires  int64  `json:"e"`
}

// shauthSession is server-side authentication state. The browser receives only
// its cryptographically random opaque identifier, never the ID token or claims.
type shauthSession struct {
	Issuer        string    `json:"issuer"`
	ClientID      string    `json:"client_id"`
	Subject       string    `json:"subject"`
	SID           string    `json:"sid,omitempty"`
	IDToken       string    `json:"id_token"`
	Name          string    `json:"name"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	Picture       string    `json:"picture"`
	Role          string    `json:"role"`
	Created       time.Time `json:"created"`
	Expires       time.Time `json:"expires"`
}

type shauthProviderMetadata struct {
	EndSessionEndpoint string `json:"end_session_endpoint"`
}

type shauthLogoutClaims struct {
	Subject string                     `json:"sub"`
	SID     string                     `json:"sid"`
	Nonce   json.RawMessage            `json:"nonce"`
	JTI     string                     `json:"jti"`
	Issued  int64                      `json:"iat"`
	Expires int64                      `json:"exp"`
	Events  map[string]json.RawMessage `json:"events"`
}

func randomSHAUTHValue() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b), err
}

func (c shauthConfig) sign(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, []byte(c.clientSecret))
	_, _ = mac.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (c shauthConfig) verify(value string, destination any) error {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return fmt.Errorf("invalid signed value")
	}
	got, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("invalid signed value")
	}
	mac := hmac.New(sha256.New, []byte(c.clientSecret))
	_, _ = mac.Write([]byte(parts[0]))
	if subtle.ConstantTimeCompare(got, mac.Sum(nil)) != 1 {
		return fmt.Errorf("invalid signed value")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("invalid signed value")
	}
	return json.Unmarshal(raw, destination)
}

func (s *Server) secureCookie() bool { return os.Getenv("BLEEPLAB_INSECURE_COOKIES") != "true" }

func (s *Server) createSHAUTHSession(session shauthSession) (string, error) {
	if session.Created.IsZero() {
		session.Created = time.Now().UTC()
	}
	session.ClientID = s.shauth.clientID
	return s.shauthState.createSession(session)
}

func (s *Server) shauthSessionForRequest(r *http.Request) (string, shauthSession, bool, error) {
	cookie, err := r.Cookie(shauthSessionCookie)
	if err != nil {
		return "", shauthSession{}, false, nil
	}
	session, ok, err := s.shauthState.session(cookie.Value, time.Now())
	if err == nil && ok && (session.Issuer != s.shauth.issuer || session.ClientID != s.shauth.clientID || session.Subject == "" || session.Name == "" || session.Email == "" || !session.EmailVerified || (session.Role != "admin" && session.Role != "developer")) {
		return cookie.Value, shauthSession{}, false, nil
	}
	return cookie.Value, session, ok, err
}

func (s *Server) shauthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		browserSurface := isHumanControlPlanePath(r.URL.Path)
		controlPlaneAPI := isSHAUTHControlPlaneAPIRequest(r)
		if !s.shauth.enabled() || (!browserSurface && !controlPlaneAPI) {
			next.ServeHTTP(w, r)
			return
		}
		_, _, ok, err := s.shauthSessionForRequest(r)
		if err != nil {
			if controlPlaneAPI {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "503 Shauth session state is unavailable"})
			} else {
				http.Error(w, "Shauth session state is unavailable", http.StatusServiceUnavailable)
			}
			return
		}
		if ok {
			next.ServeHTTP(w, r)
			return
		}
		if controlPlaneAPI {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "401 Unauthorized"})
			return
		}
		returnTo := safeReturnTo(r.URL.RequestURI())
		http.Redirect(w, r, "/auth/shauth?return_to="+url.QueryEscape(returnTo), http.StatusFound)
	})
}

func safeReturnTo(value string) string {
	u, err := url.Parse(value)
	if err != nil || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.HasPrefix(u.Path, "//") || strings.Contains(value, `\`) || strings.Contains(u.Path, `\`) || u.IsAbs() || u.Host != "" {
		return "/ui/"
	}
	if u.Path == "/ui" {
		return "/ui/"
	}
	if !strings.HasPrefix(u.Path, "/ui/") {
		return "/ui/"
	}
	return u.RequestURI()
}

func shauthOAuthConfig(provider *oidc.Provider, clientID, clientSecret, redirectURL string, scopes []string) oauth2.Config {
	endpoint := provider.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	return oauth2.Config{ClientID: clientID, ClientSecret: clientSecret, Endpoint: endpoint, RedirectURL: redirectURL, Scopes: scopes}
}

func (s *Server) handleSHAUTHLogin(w http.ResponseWriter, r *http.Request) {
	if !s.shauth.enabled() {
		http.Error(w, "Shauth is not configured", http.StatusServiceUnavailable)
		return
	}
	provider, err := oidc.NewProvider(r.Context(), s.shauth.issuer)
	if err != nil {
		http.Error(w, "Shauth discovery failed", http.StatusBadGateway)
		return
	}
	state, err := randomSHAUTHValue()
	if err != nil {
		http.Error(w, "could not create Shauth transaction", http.StatusInternalServerError)
		return
	}
	nonce, err := randomSHAUTHValue()
	if err != nil {
		http.Error(w, "could not create Shauth transaction", http.StatusInternalServerError)
		return
	}
	verifier, err := randomSHAUTHValue()
	if err != nil {
		http.Error(w, "could not create Shauth transaction", http.StatusInternalServerError)
		return
	}
	tx, err := s.shauth.sign(shauthTransaction{State: state, Nonce: nonce, Verifier: verifier, ReturnTo: safeReturnTo(r.URL.Query().Get("return_to")), Expires: time.Now().Add(10 * time.Minute).Unix()})
	if err != nil {
		http.Error(w, "could not create Shauth transaction", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: shauthTransactionCookie, Value: tx, Path: "/auth/shauth", HttpOnly: true, Secure: s.secureCookie(), SameSite: http.SameSiteLaxMode, MaxAge: 600})
	cfg := shauthOAuthConfig(provider, s.shauth.clientID, s.shauth.clientSecret, s.shauth.publicURL+"/auth/shauth/callback", []string{oidc.ScopeOpenID, "profile", "email"})
	http.Redirect(w, r, cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

func (s *Server) handleSHAUTHCallback(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(shauthTransactionCookie)
	if err != nil {
		http.Error(w, "Shauth transaction is missing", http.StatusBadRequest)
		return
	}
	var tx shauthTransaction
	if err = s.shauth.verify(cookie.Value, &tx); err != nil || tx.Expires < time.Now().Unix() || subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("state")), []byte(tx.State)) != 1 {
		http.Error(w, "Shauth transaction is invalid", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: shauthTransactionCookie, Path: "/auth/shauth", MaxAge: -1, HttpOnly: true, Secure: s.secureCookie(), SameSite: http.SameSiteLaxMode})
	provider, err := oidc.NewProvider(r.Context(), s.shauth.issuer)
	if err != nil {
		http.Error(w, "Shauth discovery failed", http.StatusBadGateway)
		return
	}
	cfg := shauthOAuthConfig(provider, s.shauth.clientID, s.shauth.clientSecret, s.shauth.publicURL+"/auth/shauth/callback", nil)
	tokens, err := cfg.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(tx.Verifier))
	if err != nil {
		http.Error(w, "Shauth code exchange failed", http.StatusUnauthorized)
		return
	}
	rawIDToken, ok := tokens.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		http.Error(w, "Shauth did not return an ID token", http.StatusUnauthorized)
		return
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: s.shauth.clientID}).Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "Shauth ID token verification failed", http.StatusUnauthorized)
		return
	}
	var claims struct {
		Nonce             string `json:"nonce"`
		SID               string `json:"sid"`
		PreferredUsername string `json:"preferred_username"`
		Email             string `json:"email"`
		EmailVerified     bool   `json:"email_verified"`
		Picture           string `json:"picture"`
		Role              string `json:"role"`
	}
	if idToken.Claims(&claims) != nil || claims.Nonce != tx.Nonce || idToken.Subject == "" || claims.PreferredUsername == "" || claims.Email == "" || !claims.EmailVerified || (claims.Role != "admin" && claims.Role != "developer") {
		http.Error(w, "Shauth identity is not authorized", http.StatusForbidden)
		return
	}
	expires := idToken.Expiry
	if maximum := time.Now().Add(shauthMaximumSessionLifetime); expires.After(maximum) {
		expires = maximum
	}
	sessionID, err := s.createSHAUTHSession(shauthSession{
		Issuer: idToken.Issuer, Subject: idToken.Subject, SID: claims.SID, IDToken: rawIDToken,
		Name: claims.PreferredUsername, Email: claims.Email, EmailVerified: claims.EmailVerified, Picture: claims.Picture, Role: claims.Role, Expires: expires,
	})
	if err != nil {
		http.Error(w, "could not create Shauth session", http.StatusInternalServerError)
		return
	}
	maxAge := int(time.Until(expires).Seconds())
	http.SetCookie(w, &http.Cookie{Name: shauthSessionCookie, Value: sessionID, Path: "/", HttpOnly: true, Secure: s.secureCookie(), SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
	http.Redirect(w, r, tx.ReturnTo, http.StatusFound)
}

func (s *Server) handleSHAUTHLogout(w http.ResponseWriter, r *http.Request) {
	if !s.shauth.enabled() {
		http.Error(w, "Shauth is not configured", http.StatusServiceUnavailable)
		return
	}
	if origin := r.Header.Get("Origin"); origin != s.shauth.publicURL {
		http.Error(w, "cross-origin logout denied", http.StatusForbidden)
		return
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		http.Error(w, "cross-origin logout denied", http.StatusForbidden)
		return
	}
	session, ok, err := s.clearSHAUTHSessionForLogout(w, r)
	if err != nil {
		http.Error(w, "Shauth session state is unavailable", http.StatusServiceUnavailable)
		return
	}
	provider, err := oidc.NewProvider(r.Context(), s.shauth.issuer)
	if err != nil {
		http.Error(w, "Shauth discovery failed", http.StatusBadGateway)
		return
	}
	var metadata shauthProviderMetadata
	if err := provider.Claims(&metadata); err != nil || metadata.EndSessionEndpoint == "" {
		http.Error(w, "Shauth does not advertise RP-Initiated Logout", http.StatusBadGateway)
		return
	}
	endpoint, err := s.shauth.logoutEndpoint(metadata.EndSessionEndpoint)
	if err != nil {
		http.Error(w, "Shauth advertised an invalid logout endpoint", http.StatusBadGateway)
		return
	}
	query := endpoint.Query()
	if ok {
		query.Set("id_token_hint", session.IDToken)
	}
	query.Set("client_id", s.shauth.clientID)
	query.Set("post_logout_redirect_uri", s.shauth.signedOutURL())
	endpoint.RawQuery = query.Encode()
	http.Redirect(w, r, endpoint.String(), http.StatusFound)
}

func (s *Server) clearSHAUTHSessionForLogout(w http.ResponseWriter, r *http.Request) (shauthSession, bool, error) {
	sessionID, session, ok, readErr := s.shauthSessionForRequest(r)
	if sessionID != "" {
		if err := s.shauthState.deleteSession(sessionID); err != nil {
			return shauthSession{}, false, err
		}
	}
	http.SetCookie(w, &http.Cookie{Name: shauthSessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.secureCookie(), SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: shauthTransactionCookie, Path: "/auth/shauth", MaxAge: -1, HttpOnly: true, Secure: s.secureCookie(), SameSite: http.SameSiteLaxMode})
	if readErr != nil {
		return shauthSession{}, false, nil
	}
	return session, ok, nil
}

func (c shauthConfig) logoutEndpoint(raw string) (*url.URL, error) {
	issuer, err := url.Parse(c.issuer)
	if err != nil {
		return nil, err
	}
	endpoint, err := url.Parse(raw)
	if err != nil || !c.validOIDCURL(endpoint) || endpoint.Fragment != "" || !strings.EqualFold(endpoint.Scheme, issuer.Scheme) || !strings.EqualFold(endpoint.Host, issuer.Host) {
		return nil, fmt.Errorf("logout endpoint origin differs from issuer")
	}
	return endpoint, nil
}

func (s *Server) handleSHAUTHFrontChannelLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors *")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	issuer := r.URL.Query().Get("iss")
	sid := r.URL.Query().Get("sid")
	if s.shauth.enabled() && issuer == s.shauth.issuer && sid != "" {
		_, browserSession, browserSessionOK, err := s.shauthSessionForRequest(r)
		if err != nil {
			http.Error(w, "Shauth session state is unavailable", http.StatusServiceUnavailable)
			return
		}
		if err := s.shauthState.deleteSessions(issuer, s.shauth.clientID, sid, ""); err != nil {
			http.Error(w, "Shauth session state is unavailable", http.StatusServiceUnavailable)
			return
		}
		if !browserSessionOK || (browserSession.Issuer == issuer && browserSession.ClientID == s.shauth.clientID && browserSession.SID == sid) {
			http.SetCookie(w, &http.Cookie{Name: shauthSessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.secureCookie(), SameSite: http.SameSiteLaxMode})
		}
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Signed out</title></head><body></body></html>`))
}

func (s *Server) handleSHAUTHSignedOut(w http.ResponseWriter, r *http.Request) {
	if s.shauth.enabled() {
		if _, _, err := s.clearSHAUTHSessionForLogout(w, r); err != nil {
			http.Error(w, "Shauth session state is unavailable", http.StatusServiceUnavailable)
			return
		}
	} else {
		http.SetCookie(w, &http.Cookie{Name: shauthSessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.secureCookie(), SameSite: http.SameSiteLaxMode})
		http.SetCookie(w, &http.Cookie{Name: shauthTransactionCookie, Path: "/auth/shauth", MaxAge: -1, HttpOnly: true, Secure: s.secureCookie(), SameSite: http.SameSiteLaxMode})
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(shauthSignedOutHTML))
}

func handleSHAUTHSignedOutStyles(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(shauthSignedOutCSS))
}

func (s *Server) handleSHAUTHBackChannelLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.shauth.enabled() {
		http.Error(w, "Shauth is not configured", http.StatusServiceUnavailable)
		return
	}
	if contentType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])); contentType != "application/x-www-form-urlencoded" {
		http.Error(w, "invalid logout content type", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid logout request", http.StatusBadRequest)
		return
	}
	logoutTokens := r.PostForm["logout_token"]
	if len(logoutTokens) != 1 || logoutTokens[0] == "" {
		http.Error(w, "logout_token is required", http.StatusBadRequest)
		return
	}
	raw := logoutTokens[0]
	provider, err := oidc.NewProvider(r.Context(), s.shauth.issuer)
	if err != nil {
		http.Error(w, "Shauth discovery failed", http.StatusBadGateway)
		return
	}
	token, err := provider.Verifier(&oidc.Config{ClientID: s.shauth.clientID}).Verify(r.Context(), raw)
	if err != nil {
		s.logger.Warn().Err(err).Msg("verify Shauth Back-Channel Logout token")
		http.Error(w, "logout token verification failed", http.StatusBadRequest)
		return
	}
	var claims shauthLogoutClaims
	claimsErr := token.Claims(&claims)
	if claimsErr != nil || claims.JTI == "" || claims.Issued == 0 || claims.Expires == 0 || len(claims.Nonce) != 0 || (claims.SID == "" && claims.Subject == "") {
		s.logger.Warn().Err(claimsErr).
			Bool("has_jti", claims.JTI != "").Bool("has_iat", claims.Issued != 0).
			Bool("has_exp", claims.Expires != 0).Bool("has_nonce", len(claims.Nonce) != 0).
			Bool("has_sid", claims.SID != "").Bool("has_sub", claims.Subject != "").
			Int("event_count", len(claims.Events)).Msg("reject Shauth Back-Channel Logout claims")
		http.Error(w, "logout token claims are invalid", http.StatusBadRequest)
		return
	}
	event, ok := claims.Events[backChannelLogoutEvent]
	var eventObject map[string]json.RawMessage
	if !ok || json.Unmarshal(event, &eventObject) != nil || eventObject == nil {
		s.logger.Warn().Bool("has_logout_event", ok).Int("event_count", len(claims.Events)).Msg("reject Shauth Back-Channel Logout event")
		http.Error(w, "logout token event is invalid", http.StatusBadRequest)
		return
	}
	now := time.Now()
	issued := time.Unix(claims.Issued, 0)
	expires := time.Unix(claims.Expires, 0)
	if !expires.After(now) || issued.Before(now.Add(-5*time.Minute)) || issued.After(now.Add(time.Minute)) {
		http.Error(w, "logout token is stale", http.StatusBadRequest)
		return
	}
	retainUntil := issued.Add(shauthMaximumSessionLifetime)
	if expires.After(retainUntil) {
		retainUntil = expires
	}
	claimed, err := s.shauthState.claimLogout(shauthLogoutClaim{
		Issuer:   token.Issuer,
		ClientID: s.shauth.clientID,
		JTI:      claims.JTI,
		SID:      claims.SID,
		Subject:  claims.Subject,
		Issued:   issued.UTC(),
		Expires:  retainUntil.UTC(),
	}, now)
	if err != nil {
		http.Error(w, "Shauth session state is unavailable", http.StatusServiceUnavailable)
		return
	}
	if !claimed {
		http.Error(w, "logout token was already used", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

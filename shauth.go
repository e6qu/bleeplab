package bleeplab

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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

type shauthConfig struct{ issuer, clientID, clientSecret, publicURL string }

func shauthConfigFromEnv() shauthConfig {
	return shauthConfig{issuer: strings.TrimRight(os.Getenv("BLEEPLAB_SHAUTH_ISSUER"), "/"), clientID: os.Getenv("BLEEPLAB_SHAUTH_CLIENT_ID"), clientSecret: os.Getenv("BLEEPLAB_SHAUTH_CLIENT_SECRET"), publicURL: strings.TrimRight(os.Getenv("BLEEPLAB_PUBLIC_URL"), "/")}
}
func (c shauthConfig) enabled() bool {
	return c.issuer != "" && c.clientID != "" && c.clientSecret != "" && c.publicURL != ""
}
func (c shauthConfig) validate() error {
	n := 0
	for _, v := range []string{c.issuer, c.clientID, c.clientSecret, c.publicURL} {
		if v != "" {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	if n != 4 {
		return fmt.Errorf("all BLEEPPLAB_SHAUTH_* and BLEEPPLAB_PUBLIC_URL values must be configured together")
	}
	for _, v := range []string{c.issuer, c.publicURL} {
		u, e := url.Parse(v)
		if e != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("Shauth issuer and public URL must be absolute HTTPS URLs")
		}
	}
	return nil
}

type shauthTransaction struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Expires  int64  `json:"e"`
}
type shauthSession struct {
	Subject string `json:"s"`
	Name    string `json:"n"`
	Role    string `json:"r"`
	Expires int64  `json:"e"`
}

func randomSHAUTHValue() (string, error) {
	b := make([]byte, 32)
	_, e := rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b), e
}
func (c shauthConfig) sign(value any) (string, error) {
	raw, e := json.Marshal(value)
	if e != nil {
		return "", e
	}
	p := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, []byte(c.clientSecret))
	_, _ = mac.Write([]byte(p))
	return p + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
func (c shauthConfig) verify(value string, destination any) error {
	p := strings.Split(value, ".")
	if len(p) != 2 {
		return fmt.Errorf("invalid signed value")
	}
	got, e := base64.RawURLEncoding.DecodeString(p[1])
	if e != nil {
		return fmt.Errorf("invalid signed value")
	}
	mac := hmac.New(sha256.New, []byte(c.clientSecret))
	_, _ = mac.Write([]byte(p[0]))
	if subtle.ConstantTimeCompare(got, mac.Sum(nil)) != 1 {
		return fmt.Errorf("invalid signed value")
	}
	raw, e := base64.RawURLEncoding.DecodeString(p[0])
	if e != nil {
		return fmt.Errorf("invalid signed value")
	}
	return json.Unmarshal(raw, destination)
}
func (s *Server) secureCookie() bool { return os.Getenv("BLEEPLAB_INSECURE_COOKIES") != "true" }
func (s *Server) shauthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.shauth.enabled() || !isHumanControlPlanePath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		c, e := r.Cookie(shauthSessionCookie)
		var session shauthSession
		if e == nil {
			e = s.shauth.verify(c.Value, &session)
		}
		if e == nil && session.Expires > time.Now().Unix() {
			next.ServeHTTP(w, r)
			return
		}
		http.Redirect(w, r, "/auth/shauth", http.StatusFound)
	})
}
func (s *Server) handleSHAUTHLogin(w http.ResponseWriter, r *http.Request) {
	if !s.shauth.enabled() {
		http.Error(w, "Shauth is not configured", http.StatusServiceUnavailable)
		return
	}
	p, e := oidc.NewProvider(r.Context(), s.shauth.issuer)
	if e != nil {
		http.Error(w, "Shauth discovery failed", http.StatusBadGateway)
		return
	}
	state, e := randomSHAUTHValue()
	if e != nil {
		http.Error(w, "could not create Shauth transaction", 500)
		return
	}
	nonce, e := randomSHAUTHValue()
	if e != nil {
		http.Error(w, "could not create Shauth transaction", 500)
		return
	}
	verifier, e := randomSHAUTHValue()
	if e != nil {
		http.Error(w, "could not create Shauth transaction", 500)
		return
	}
	tx, e := s.shauth.sign(shauthTransaction{state, nonce, verifier, time.Now().Add(10 * time.Minute).Unix()})
	if e != nil {
		http.Error(w, "could not create Shauth transaction", 500)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: shauthTransactionCookie, Value: tx, Path: "/auth/shauth", HttpOnly: true, Secure: s.secureCookie(), SameSite: http.SameSiteLaxMode, MaxAge: 600})
	cfg := oauth2.Config{ClientID: s.shauth.clientID, ClientSecret: s.shauth.clientSecret, Endpoint: p.Endpoint(), RedirectURL: s.shauth.publicURL + "/auth/shauth/callback", Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}
	http.Redirect(w, r, cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}
func (s *Server) handleSHAUTHCallback(w http.ResponseWriter, r *http.Request) {
	c, e := r.Cookie(shauthTransactionCookie)
	if e != nil {
		http.Error(w, "Shauth transaction is missing", 400)
		return
	}
	var tx shauthTransaction
	if e = s.shauth.verify(c.Value, &tx); e != nil || tx.Expires < time.Now().Unix() || subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("state")), []byte(tx.State)) != 1 {
		http.Error(w, "Shauth transaction is invalid", 400)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: shauthTransactionCookie, Path: "/auth/shauth", MaxAge: -1, HttpOnly: true, Secure: s.secureCookie(), SameSite: http.SameSiteLaxMode})
	p, e := oidc.NewProvider(r.Context(), s.shauth.issuer)
	if e != nil {
		http.Error(w, "Shauth discovery failed", 502)
		return
	}
	cfg := oauth2.Config{ClientID: s.shauth.clientID, ClientSecret: s.shauth.clientSecret, Endpoint: p.Endpoint(), RedirectURL: s.shauth.publicURL + "/auth/shauth/callback"}
	tokens, e := cfg.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(tx.Verifier))
	if e != nil {
		http.Error(w, "Shauth code exchange failed", 401)
		return
	}
	raw, ok := tokens.Extra("id_token").(string)
	if !ok {
		http.Error(w, "Shauth did not return an ID token", 401)
		return
	}
	token, e := p.Verifier(&oidc.Config{ClientID: s.shauth.clientID}).Verify(r.Context(), raw)
	if e != nil {
		http.Error(w, "Shauth ID token verification failed", 401)
		return
	}
	var claims struct {
		Nonce             string `json:"nonce"`
		PreferredUsername string `json:"preferred_username"`
		Role              string `json:"role"`
	}
	if token.Claims(&claims) != nil || claims.Nonce != tx.Nonce || (claims.Role != "admin" && claims.Role != "developer") {
		http.Error(w, "Shauth identity is not authorized", 403)
		return
	}
	v, e := s.shauth.sign(shauthSession{token.Subject, claims.PreferredUsername, claims.Role, time.Now().Add(8 * time.Hour).Unix()})
	if e != nil {
		http.Error(w, "could not create Shauth session", 500)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: shauthSessionCookie, Value: v, Path: "/", HttpOnly: true, Secure: s.secureCookie(), SameSite: http.SameSiteLaxMode, MaxAge: 8 * 60 * 60})
	http.Redirect(w, r, "/ui/", http.StatusFound)
}
func (s *Server) handleSHAUTHLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: shauthSessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.secureCookie(), SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/ui/", http.StatusFound)
}

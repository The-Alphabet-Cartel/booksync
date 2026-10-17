// Package hardcoveroauth connects a booksync profile to a member's Hardcover
// account with OAuth 2.0 (Booksync F3): authorization code with PKCE (S256),
// a confidential client, the RFC 9207 issuer check, refresh, and revocation.
package hardcoveroauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// Hardcover's endpoints, from its discovery document
// (https://api.hardcover.app/.well-known/oauth-authorization-server, read
// 5 Oct 2026). The authorization page lives on hardcover.app; everything else
// on api.hardcover.app.
const (
	Issuer        = "https://api.hardcover.app"
	AuthURL       = "https://hardcover.app/oauth2/authorize"
	TokenURL      = "https://api.hardcover.app/oauth2/token"
	RevokeURL     = "https://api.hardcover.app/oauth2/revoke"
	DefaultAPIURL = "https://api.hardcover.app/v1/graphql"
)

// Scopes are exactly the five booksync needs. Never "all", never write:catalog*.
var Scopes = []string{
	"read:me:content",
	"read:catalog:search",
	"read:catalog:data",
	"read:library:private",
	"write:library",
}

// StateTTL is how long a started connection waits for Hardcover's callback.
const StateTTL = 10 * time.Minute

var (
	// ErrNotConfigured means the client id, secret or redirect URI is missing.
	ErrNotConfigured = errors.New("hardcover oauth is not configured")
	// ErrStateUnknown means the callback's state was never issued or already used.
	ErrStateUnknown = errors.New("unknown or already used oauth state")
	// ErrStateExpired means the member took longer than StateTTL.
	ErrStateExpired = errors.New("oauth state expired")
	// ErrStateUser means the callback arrived in a different member's session.
	ErrStateUser = errors.New("oauth state belongs to another user")
	// ErrIssuer means the callback's iss was missing or not Hardcover's.
	ErrIssuer = errors.New("oauth callback issuer mismatch")
	// ErrDenied means Hardcover returned an error instead of a code.
	ErrDenied = errors.New("hardcover authorization was not granted")
	// ErrReconnectRequired means Hardcover refused the refresh token: the member
	// revoked booksync on Hardcover, or the grant is otherwise gone.
	ErrReconnectRequired = errors.New("hardcover connection must be renewed")
)

// Config is the confidential client. The endpoint fields default to
// Hardcover's; tests point them at a fake server.
type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AuthURL      string
	TokenURL     string
	RevokeURL    string
	APIURL       string
	HTTPClient   *http.Client
}

// Enabled reports whether the client is fully configured.
func (c Config) Enabled() bool {
	return c.ClientID != "" && c.ClientSecret != "" && c.RedirectURL != ""
}

func (c Config) withDefaults() Config {
	if c.AuthURL == "" {
		c.AuthURL = AuthURL
	}
	if c.TokenURL == "" {
		c.TokenURL = TokenURL
	}
	if c.RevokeURL == "" {
		c.RevokeURL = RevokeURL
	}
	if c.APIURL == "" {
		c.APIURL = DefaultAPIURL
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	return c
}

func (c Config) oauth2Config() *oauth2.Config {
	c = c.withDefaults()
	return &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  c.RedirectURL,
		Scopes:       Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:   c.AuthURL,
			TokenURL:  c.TokenURL,
			AuthStyle: oauth2.AuthStyleInHeader, // client_secret_basic
		},
	}
}

func (c Config) context(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, c.withDefaults().HTTPClient)
}

// AuthCodeURL is where the member's browser is sent to approve booksync.
func (c Config) AuthCodeURL(state, verifier string) string {
	return c.oauth2Config().AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
}

// Exchange trades the callback's code for a token set.
func (c Config) Exchange(ctx context.Context, code, verifier string) (*oauth2.Token, error) {
	if !c.Enabled() {
		return nil, ErrNotConfigured
	}
	return c.oauth2Config().Exchange(c.context(ctx), code, oauth2.VerifierOption(verifier))
}

// Revoke revokes a token at Hardcover. Revoking either token of a pair
// revokes both (Hardcover's documentation).
func (c Config) Revoke(ctx context.Context, token, hint string) error {
	if !c.Enabled() {
		return ErrNotConfigured
	}
	c = c.withDefaults()
	form := url.Values{"token": {token}}
	if hint != "" {
		form.Set("token_type_hint", hint)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.RevokeURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.ClientSecret))
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("revoke request failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revoke returned status %d", resp.StatusCode)
	}
	return nil
}

// FetchUsername asks Hardcover which account a token belongs to, for display.
func (c Config) FetchUsername(ctx context.Context, accessToken string) (string, error) {
	c = c.withDefaults()
	body, _ := json.Marshal(map[string]string{"query": "query BooksyncMe { me { username } }"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.APIURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("me request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("me returned status %d", resp.StatusCode)
	}
	var result struct {
		Data struct {
			Me []struct {
				Username string `json:"username"`
			} `json:"me"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return "", fmt.Errorf("decode me response: %w", err)
	}
	if len(result.Data.Me) == 0 || result.Data.Me[0].Username == "" {
		return "", fmt.Errorf("me response has no username")
	}
	return result.Data.Me[0].Username, nil
}

// CheckCallback validates Hardcover's redirect back to booksync and returns
// its code and state. The issuer is checked first, on error responses too
// (RFC 9207; Hardcover advertises authorization_response_iss_parameter_supported).
func CheckCallback(query url.Values) (code, state string, err error) {
	if query.Get("iss") != Issuer {
		return "", "", ErrIssuer
	}
	if e := query.Get("error"); e != "" {
		return "", "", fmt.Errorf("%w: %s", ErrDenied, e)
	}
	code, state = query.Get("code"), query.Get("state")
	if code == "" || state == "" {
		return "", "", fmt.Errorf("%w: missing code or state", ErrDenied)
	}
	return code, state, nil
}

// Pending is a connection waiting for Hardcover's callback.
type Pending struct {
	ProfileID string
	UserID    string
	Verifier  string
	expires   time.Time
}

// StateStore holds pending connections in memory. A restart drops them; the
// member simply clicks Connect again.
type StateStore struct {
	mu      sync.Mutex
	pending map[string]Pending
	now     func() time.Time
}

// NewStateStore returns an empty store.
func NewStateStore() *StateStore {
	return &StateStore{pending: make(map[string]Pending), now: time.Now}
}

// Begin records a new pending connection and returns its state and PKCE
// verifier.
func (s *StateStore) Begin(profileID, userID string) (state, verifier string) {
	state = randomToken()
	verifier = oauth2.GenerateVerifier()
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for key, p := range s.pending {
		if now.After(p.expires) {
			delete(s.pending, key)
		}
	}
	s.pending[state] = Pending{ProfileID: profileID, UserID: userID, Verifier: verifier, expires: now.Add(StateTTL)}
	return state, verifier
}

// Take consumes a state. It is single-use whatever the outcome.
func (s *StateStore) Take(state, userID string) (Pending, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[state]
	if !ok {
		return Pending{}, ErrStateUnknown
	}
	delete(s.pending, state)
	if s.now().After(p.expires) {
		return Pending{}, ErrStateExpired
	}
	if p.UserID != userID {
		return Pending{}, ErrStateUser
	}
	return p, nil
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// storedToken is the JSON kept, encrypted, in the profile's Hardcover token
// column.
type storedToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type,omitempty"`
	Expiry       time.Time `json:"expiry"`
}

// EncodeToken serialises a token set for storage.
func EncodeToken(t *oauth2.Token) (string, error) {
	if t == nil || t.AccessToken == "" {
		return "", fmt.Errorf("no access token to store")
	}
	b, err := json.Marshal(storedToken{AccessToken: t.AccessToken, RefreshToken: t.RefreshToken, TokenType: t.TokenType, Expiry: t.Expiry})
	return string(b), err
}

// DecodeToken reads a stored token set.
func DecodeToken(s string) (*oauth2.Token, error) {
	var st storedToken
	if err := json.Unmarshal([]byte(s), &st); err != nil {
		return nil, fmt.Errorf("stored hardcover token is not an oauth token set: %w", err)
	}
	if st.AccessToken == "" {
		return nil, fmt.Errorf("stored hardcover token has no access token")
	}
	return &oauth2.Token{AccessToken: st.AccessToken, RefreshToken: st.RefreshToken, TokenType: st.TokenType, Expiry: st.Expiry}, nil
}

// TokenSource returns a source that refreshes an expired access token, calls
// onRotate whenever the token set changes (so a rotated refresh token is
// saved), and on a refused refresh calls onRejected once and returns
// ErrReconnectRequired -- no retries.
func (c Config) TokenSource(ctx context.Context, t *oauth2.Token, onRotate func(*oauth2.Token) error, onRejected func()) oauth2.TokenSource {
	return &persistingSource{
		base:       c.oauth2Config().TokenSource(c.context(ctx), t),
		last:       t,
		onRotate:   onRotate,
		onRejected: onRejected,
	}
}

type persistingSource struct {
	mu         sync.Mutex
	base       oauth2.TokenSource
	last       *oauth2.Token
	rejected   bool
	onRotate   func(*oauth2.Token) error
	onRejected func()
}

func (p *persistingSource) Token() (*oauth2.Token, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.rejected {
		return nil, ErrReconnectRequired
	}
	t, err := p.base.Token()
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) && re.ErrorCode == "invalid_grant" {
			p.rejected = true
			if p.onRejected != nil {
				p.onRejected()
			}
			return nil, ErrReconnectRequired
		}
		return nil, fmt.Errorf("hardcover token refresh failed: %w", err)
	}
	if p.last == nil || t.AccessToken != p.last.AccessToken || t.RefreshToken != p.last.RefreshToken {
		if p.onRotate != nil {
			if err := p.onRotate(t); err != nil {
				return nil, fmt.Errorf("save refreshed hardcover token: %w", err)
			}
		}
		p.last = t
	}
	return t, nil
}

package hardcoveroauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// fakeHardcover is a token, revoke and GraphQL server standing in for
// api.hardcover.app.
type fakeHardcover struct {
	*httptest.Server
	refreshCalls  atomic.Int32
	rotate        bool
	rejectRefresh bool
	lastExchange  url.Values
	lastRevoke    url.Values
	revokeStatus  int
}

func newFakeHardcover(t *testing.T) *fakeHardcover {
	t.Helper()
	f := &fakeHardcover{revokeStatus: http.StatusOK}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		switch r.URL.Path {
		case "/oauth2/token":
			require.NoError(t, r.ParseForm())
			if !ok || user != "client-id" || pass != "client-secret" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			switch r.Form.Get("grant_type") {
			case "authorization_code":
				f.lastExchange = r.Form
				_, _ = w.Write([]byte(`{"access_token":"hc_at_1","refresh_token":"hc_rt_1","token_type":"Bearer","expires_in":3600}`))
			case "refresh_token":
				n := f.refreshCalls.Add(1)
				if f.rejectRefresh {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
					return
				}
				body := map[string]interface{}{"access_token": "hc_at_refreshed_" + string(rune('0'+n)), "token_type": "Bearer", "expires_in": 3600}
				if f.rotate {
					body["refresh_token"] = "hc_rt_rotated_" + string(rune('0'+n))
				}
				_ = json.NewEncoder(w).Encode(body)
			default:
				w.WriteHeader(http.StatusBadRequest)
			}
		case "/oauth2/revoke":
			require.NoError(t, r.ParseForm())
			f.lastRevoke = r.Form
			if !ok || user != "client-id" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(f.revokeStatus)
		case "/v1/graphql":
			if r.Header.Get("Authorization") != "Bearer hc_at_1" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"data":{"me":[{"username":"pb-reads"}]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeHardcover) config() Config {
	return Config{
		ClientID: "client-id", ClientSecret: "client-secret",
		RedirectURL: "https://booksync.example.invalid/auth/hardcover/callback",
		TokenURL:    f.URL + "/oauth2/token", RevokeURL: f.URL + "/oauth2/revoke", APIURL: f.URL + "/v1/graphql",
	}
}

func TestAuthCodeURLAsksForExactlyTheFiveScopesWithS256(t *testing.T) {
	cfg := Config{ClientID: "client-id", ClientSecret: "s", RedirectURL: "https://booksync.example.invalid/cb"}
	u, err := url.Parse(cfg.AuthCodeURL("the-state", "the-verifier"))
	require.NoError(t, err)
	require.Equal(t, "https://hardcover.app/oauth2/authorize", u.Scheme+"://"+u.Host+u.Path)
	q := u.Query()
	require.Equal(t, "code", q.Get("response_type"))
	require.Equal(t, "client-id", q.Get("client_id"))
	require.Equal(t, "the-state", q.Get("state"))
	require.Equal(t, "S256", q.Get("code_challenge_method"))
	require.Equal(t, oauth2.S256ChallengeFromVerifier("the-verifier"), q.Get("code_challenge"))
	require.Equal(t, "read:me:content read:catalog:search read:catalog:data read:library:private write:library", q.Get("scope"))
	require.NotContains(t, q.Get("scope"), "all")
	require.NotContains(t, q.Get("scope"), "catalog:edit")
}

func TestCheckCallback(t *testing.T) {
	for _, test := range []struct {
		name    string
		query   string
		wantErr error
	}{
		{name: "good", query: "code=c&state=s&iss=https%3A%2F%2Fapi.hardcover.app"},
		{name: "missing iss", query: "code=c&state=s", wantErr: ErrIssuer},
		{name: "wrong iss", query: "code=c&state=s&iss=https%3A%2F%2Fevil.example", wantErr: ErrIssuer},
		{name: "denied", query: "error=access_denied&state=s&iss=https%3A%2F%2Fapi.hardcover.app", wantErr: ErrDenied},
		{name: "denied without iss is an issuer failure first", query: "error=access_denied&state=s", wantErr: ErrIssuer},
		{name: "no code", query: "state=s&iss=https%3A%2F%2Fapi.hardcover.app", wantErr: ErrDenied},
	} {
		t.Run(test.name, func(t *testing.T) {
			q, _ := url.ParseQuery(test.query)
			code, state, err := CheckCallback(q)
			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, "c", code)
			require.Equal(t, "s", state)
		})
	}
}

func TestStateStoreIsSingleUseBoundAndExpiring(t *testing.T) {
	store := NewStateStore()
	now := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	state, verifier := store.Begin("profile-1", "user-a")
	require.NotEmpty(t, state)
	require.NotEmpty(t, verifier)

	p, err := store.Take(state, "user-a")
	require.NoError(t, err)
	require.Equal(t, Pending{ProfileID: "profile-1", UserID: "user-a", Verifier: verifier, expires: now.Add(StateTTL)}, p)
	_, err = store.Take(state, "user-a")
	require.ErrorIs(t, err, ErrStateUnknown, "a state is single-use")

	state, _ = store.Begin("profile-1", "user-a")
	_, err = store.Take(state, "user-b")
	require.ErrorIs(t, err, ErrStateUser)
	_, err = store.Take(state, "user-a")
	require.ErrorIs(t, err, ErrStateUnknown, "a mismatched take still consumes the state")

	state, _ = store.Begin("profile-1", "user-a")
	now = now.Add(StateTTL + time.Second)
	_, err = store.Take(state, "user-a")
	require.ErrorIs(t, err, ErrStateExpired)

	_, err = store.Take("never-issued", "user-a")
	require.ErrorIs(t, err, ErrStateUnknown)
}

func TestExchangeUsesClientSecretBasicAndVerifier(t *testing.T) {
	f := newFakeHardcover(t)
	tok, err := f.config().Exchange(context.Background(), "the-code", "the-verifier")
	require.NoError(t, err)
	require.Equal(t, "hc_at_1", tok.AccessToken)
	require.Equal(t, "hc_rt_1", tok.RefreshToken)
	require.Equal(t, "the-code", f.lastExchange.Get("code"))
	require.Equal(t, "the-verifier", f.lastExchange.Get("code_verifier"))
	require.Empty(t, f.lastExchange.Get("client_secret"), "the secret goes in the Authorization header, not the body")

	name, err := f.config().FetchUsername(context.Background(), tok.AccessToken)
	require.NoError(t, err)
	require.Equal(t, "pb-reads", name)

	_, err = Config{}.Exchange(context.Background(), "c", "v")
	require.ErrorIs(t, err, ErrNotConfigured)
}

func TestTokenRoundTrip(t *testing.T) {
	expiry := time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)
	encoded, err := EncodeToken(&oauth2.Token{AccessToken: "a", RefreshToken: "r", TokenType: "Bearer", Expiry: expiry})
	require.NoError(t, err)
	decoded, err := DecodeToken(encoded)
	require.NoError(t, err)
	require.Equal(t, "a", decoded.AccessToken)
	require.Equal(t, "r", decoded.RefreshToken)
	require.True(t, expiry.Equal(decoded.Expiry))

	_, err = DecodeToken("hc_pasted_personal_token")
	require.Error(t, err, "a pasted personal token is not an oauth token set")
	_, err = EncodeToken(&oauth2.Token{})
	require.Error(t, err)
}

func TestTokenSourceRefreshesAndSavesRotatedTokens(t *testing.T) {
	for _, rotate := range []bool{false, true} {
		t.Run(map[bool]string{false: "no rotation", true: "rotation"}[rotate], func(t *testing.T) {
			f := newFakeHardcover(t)
			f.rotate = rotate
			var saved []*oauth2.Token
			expired := &oauth2.Token{AccessToken: "hc_at_old", RefreshToken: "hc_rt_1", Expiry: time.Now().Add(-time.Minute)}
			ts := f.config().TokenSource(context.Background(), expired,
				func(t *oauth2.Token) error { saved = append(saved, t); return nil },
				func() { t.Fatal("refresh was not refused") })

			tok, err := ts.Token()
			require.NoError(t, err)
			require.Equal(t, "hc_at_refreshed_1", tok.AccessToken)
			require.Len(t, saved, 1)
			if rotate {
				require.Equal(t, "hc_rt_rotated_1", saved[0].RefreshToken)
			} else {
				require.Equal(t, "hc_rt_1", saved[0].RefreshToken, "an unrotated refresh token is kept")
			}

			// A still-valid token is reused: no second refresh, no second save.
			_, err = ts.Token()
			require.NoError(t, err)
			require.EqualValues(t, 1, f.refreshCalls.Load())
			require.Len(t, saved, 1)
		})
	}
}

func TestRefusedRefreshMarksReconnectOnceAndStops(t *testing.T) {
	f := newFakeHardcover(t)
	f.rejectRefresh = true
	rejected := 0
	expired := &oauth2.Token{AccessToken: "hc_at_old", RefreshToken: "hc_rt_revoked", Expiry: time.Now().Add(-time.Minute)}
	ts := f.config().TokenSource(context.Background(), expired,
		func(*oauth2.Token) error { t.Fatal("nothing to save"); return nil },
		func() { rejected++ })

	for i := 0; i < 3; i++ {
		_, err := ts.Token()
		require.ErrorIs(t, err, ErrReconnectRequired)
	}
	require.Equal(t, 1, rejected)
	require.EqualValues(t, 1, f.refreshCalls.Load(), "no retry loop after a refusal")
}

func TestRevoke(t *testing.T) {
	f := newFakeHardcover(t)
	require.NoError(t, f.config().Revoke(context.Background(), "hc_rt_1", "refresh_token"))
	require.Equal(t, "hc_rt_1", f.lastRevoke.Get("token"))
	require.Equal(t, "refresh_token", f.lastRevoke.Get("token_type_hint"))

	f.revokeStatus = http.StatusServiceUnavailable
	err := f.config().Revoke(context.Background(), "hc_rt_1", "refresh_token")
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrNotConfigured))
	require.True(t, strings.Contains(err.Error(), "503"))
}

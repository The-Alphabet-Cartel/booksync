package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/auth"
	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/database"
	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/hardcoveroauth"
)

// Booksync F3 route tests: Connect Hardcover, the callback, and disconnect.

func newRouteFakeHardcover(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth2/token":
			_, _ = w.Write([]byte(`{"access_token":"hc_at_route_member","refresh_token":"hc_rt_route_member","token_type":"Bearer","expires_in":3600}`))
		case "/oauth2/revoke":
			w.WriteHeader(http.StatusOK)
		case "/v1/graphql":
			_, _ = w.Write([]byte(`{"data":{"me":[{"username":"route-member-hc"}]}}`))
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func TestHardcoverRoutesConnectCallbackDisconnect(t *testing.T) {
	fixture := newRouteTestFixture(t, true)
	fake := newRouteFakeHardcover(t)
	fixture.server.multiUserService.SetHardcoverOAuthConfig(hardcoveroauth.Config{
		ClientID: "route-client", ClientSecret: "route-secret", RedirectURL: "https://booksync.invalid/auth/hardcover/callback",
		TokenURL: fake.URL + "/oauth2/token", RevokeURL: fake.URL + "/oauth2/revoke", APIURL: fake.URL + "/v1/graphql",
	})
	member := newRouteSession(t, fixture, "hc-member", auth.RoleUser)
	other := newRouteSession(t, fixture, "hc-other", auth.RoleUser)
	createRouteProfile(t, fixture, member, "hc-profile", "hc-profile-abs-token")
	require.NoError(t, fixture.repo.SetABSLink("hc-profile", "abs-hc-member", "hc-member", database.ABSLinkStateApproved))

	// Approved link but no Hardcover yet: the Sync button says so.
	response := fixture.requestWithCookies(http.MethodPost, "/api/profiles/hc-profile/sync", nil, []*http.Cookie{member.cookie})
	require.Equal(t, http.StatusConflict, response.Code, response.Body.String())
	require.Contains(t, decodeLinkEnvelope(t, response.Body.Bytes()).Error, "Connect your Hardcover")

	// Only the owner may start a connection.
	response = fixture.requestWithCookies(http.MethodGet, "/api/profiles/hc-profile/hardcover/connect", nil, []*http.Cookie{other.cookie})
	require.Equal(t, http.StatusNotFound, response.Code)
	response = fixture.request(http.MethodGet, "/api/profiles/hc-profile/hardcover/connect", nil)
	require.Equal(t, http.StatusUnauthorized, response.Code)

	response = fixture.requestWithCookies(http.MethodGet, "/api/profiles/hc-profile/hardcover/connect", nil, []*http.Cookie{member.cookie})
	require.Equal(t, http.StatusFound, response.Code, response.Body.String())
	location, err := url.Parse(response.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "hardcover.app", location.Host)
	state := location.Query().Get("state")
	require.NotEmpty(t, state)

	callback := func(query string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		return fixture.requestWithCookies(http.MethodGet, "/auth/hardcover/callback?"+query, nil, cookies)
	}
	good := url.Values{"code": {"route-code"}, "state": {state}, "iss": {hardcoveroauth.Issuer}}.Encode()

	// No session: refused before anything is spent.
	require.Equal(t, http.StatusUnauthorized, callback(good).Code)
	// Another member's session: refused, and the state is gone.
	response = callback(good, other.cookie)
	require.Equal(t, http.StatusFound, response.Code)
	require.Equal(t, "/?hardcover=error%3Astate", response.Header().Get("Location"))
	response = callback(good, member.cookie)
	require.Equal(t, "/?hardcover=error%3Astate", response.Header().Get("Location"), "the state was single-use")

	// A fresh connection, with a wrong issuer, then a good one.
	response = fixture.requestWithCookies(http.MethodGet, "/api/profiles/hc-profile/hardcover/connect", nil, []*http.Cookie{member.cookie})
	location, _ = url.Parse(response.Header().Get("Location"))
	bad := url.Values{"code": {"route-code"}, "state": {location.Query().Get("state")}, "iss": {"https://evil.invalid"}}.Encode()
	require.Equal(t, "/?hardcover=error%3Aissuer", callback(bad, member.cookie).Header().Get("Location"))

	response = fixture.requestWithCookies(http.MethodGet, "/api/profiles/hc-profile/hardcover/connect", nil, []*http.Cookie{member.cookie})
	location, _ = url.Parse(response.Header().Get("Location"))
	good = url.Values{"code": {"route-code"}, "state": {location.Query().Get("state")}, "iss": {hardcoveroauth.Issuer}}.Encode()
	response = callback(good, member.cookie)
	require.Equal(t, http.StatusFound, response.Code)
	require.Equal(t, "/?hardcover=connected", response.Header().Get("Location"))

	response = fixture.requestWithCookies(http.MethodGet, "/api/profiles/hc-profile", nil, []*http.Cookie{member.cookie})
	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, map[string]interface{}{"state": "connected", "username": "route-member-hc"},
		decodeLinkEnvelope(t, response.Body.Bytes()).Data["hardcover"])
	require.NotContains(t, response.Body.String(), "hc_at_route_member")
	require.NotContains(t, response.Body.String(), "hc_rt_route_member")

	// Another member cannot disconnect it; the owner can.
	response = fixture.requestWithCookies(http.MethodPost, "/api/profiles/hc-profile/hardcover/disconnect", nil, []*http.Cookie{other.cookie})
	require.Equal(t, http.StatusNotFound, response.Code)
	response = fixture.requestWithCookies(http.MethodPost, "/api/profiles/hc-profile/hardcover/disconnect", nil, []*http.Cookie{member.cookie})
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Equal(t, map[string]interface{}{"state": "none", "revoked": true}, decodeLinkEnvelope(t, response.Body.Bytes()).Data)

	profile, err := fixture.repo.GetProfile("hc-profile")
	require.NoError(t, err)
	require.Empty(t, profile.HardcoverToken)
}

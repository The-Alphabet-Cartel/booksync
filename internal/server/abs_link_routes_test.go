package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/api/audiobookshelf"
	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/auth"
)

// Booksync F2 route tests: the member link, the admin approval view, and the
// sync refusal while a link waits for approval.

type routeABSUsers struct{ users []audiobookshelf.UserSummary }

func (f routeABSUsers) ListUsers(context.Context) ([]audiobookshelf.UserSummary, error) {
	return f.users, nil
}

type absLinkEnvelope struct {
	Success bool                   `json:"success"`
	Error   string                 `json:"error"`
	Data    map[string]interface{} `json:"data"`
}

func decodeLinkEnvelope(t *testing.T, body []byte) absLinkEnvelope {
	t.Helper()
	var envelope absLinkEnvelope
	require.NoError(t, json.Unmarshal(body, &envelope), string(body))
	return envelope
}

func loginRouteAdmin(t *testing.T, fixture *routeTestFixture) routeSession {
	t.Helper()
	response := fixture.request(http.MethodPost, "/api/auth/login",
		[]byte(`{"provider":"local","credentials":{"username":"admin","password":"admin"}}`))
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	return routeSession{cookie: response.Result().Cookies()[0]}
}

func TestABSLinkRoutesMemberFlowAndAdminApproval(t *testing.T) {
	fixture := newRouteTestFixture(t, true)
	fixture.server.multiUserService.SetABSUserLister(routeABSUsers{users: []audiobookshelf.UserSummary{
		{ID: "abs-member", Username: "Member-One", HasOpenIDLink: true, IsActive: true},
	}})
	member := newRouteSession(t, fixture, "member-one", auth.RoleUser)
	other := newRouteSession(t, fixture, "member-two", auth.RoleUser)
	admin := loginRouteAdmin(t, fixture)

	// Creating a profile matches the owner straight away: pending.
	response := fixture.requestWithCookies(http.MethodPost, "/api/profiles", []byte(`{
		"id": "member-profile", "name": "member-profile",
		"audiobookshelf_url": "http://audiobookshelf.invalid",
		"audiobookshelf_token": "member-abs-token", "hardcover_token": "member-hc-token",
		"sync_config": {"dry_run": true}
	}`), []*http.Cookie{member.cookie})
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	created := decodeLinkEnvelope(t, response.Body.Bytes())
	require.Equal(t, map[string]interface{}{"state": "pending", "abs_username": "Member-One"}, created.Data["abs_link"])
	require.NotContains(t, created.Data, "abs_link_error")

	// The member cannot sync until an admin approves.
	response = fixture.requestWithCookies(http.MethodPost, "/api/profiles/member-profile/sync", nil, []*http.Cookie{member.cookie})
	require.Equal(t, http.StatusConflict, response.Code, response.Body.String())
	require.Contains(t, decodeLinkEnvelope(t, response.Body.Bytes()).Error, "approve")

	// Admin routes are invisible to members and closed to strangers.
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/api/admin/abs-links"},
		{http.MethodGet, "/api/admin/abs-users"},
		{http.MethodPost, "/api/admin/profiles/member-profile/abs-link/approve"},
		{http.MethodPost, "/api/admin/profiles/member-profile/abs-link/reject"},
		{http.MethodPut, "/api/admin/profiles/member-profile/abs-link"},
	} {
		response = fixture.requestWithCookies(route.method, route.path, []byte(`{"abs_user_id":"abs-member"}`), []*http.Cookie{member.cookie})
		require.Equal(t, http.StatusNotFound, response.Code, "%s %s as member: %s", route.method, route.path, response.Body.String())
		response = fixture.request(route.method, route.path, []byte(`{"abs_user_id":"abs-member"}`))
		require.Equal(t, http.StatusUnauthorized, response.Code, "%s %s anonymous", route.method, route.path)
	}

	// Another member cannot touch the owner's link.
	response = fixture.requestWithCookies(http.MethodPost, "/api/profiles/member-profile/abs-link", nil, []*http.Cookie{other.cookie})
	require.Equal(t, http.StatusNotFound, response.Code, response.Body.String())

	// The admin sees the pending link with its owner, and approves it.
	response = fixture.requestWithCookies(http.MethodGet, "/api/admin/abs-links", nil, []*http.Cookie{admin.cookie})
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var listed struct {
		Data []map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &listed))
	require.Len(t, listed.Data, 1)
	require.Equal(t, "member-profile", listed.Data[0]["profile_id"])
	require.Equal(t, "member-one", listed.Data[0]["owner_username"])
	require.Equal(t, "pending", listed.Data[0]["abs_link_state"])
	require.NotContains(t, response.Body.String(), "member-abs-token")

	response = fixture.requestWithCookies(http.MethodPost, "/api/admin/profiles/member-profile/abs-link/approve", nil, []*http.Cookie{admin.cookie})
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Equal(t, "approved", decodeLinkEnvelope(t, response.Body.Bytes()).Data["state"])

	// Approving twice is refused: it is no longer pending.
	response = fixture.requestWithCookies(http.MethodPost, "/api/admin/profiles/member-profile/abs-link/approve", nil, []*http.Cookie{admin.cookie})
	require.Equal(t, http.StatusConflict, response.Code, response.Body.String())

	// The member's own profile view now shows the approved link.
	response = fixture.requestWithCookies(http.MethodGet, "/api/profiles/member-profile", nil, []*http.Cookie{member.cookie})
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Equal(t, map[string]interface{}{"state": "approved", "abs_username": "Member-One"},
		decodeLinkEnvelope(t, response.Body.Bytes()).Data["abs_link"])
}

func TestABSLinkRoutesUnmatchedMemberIsToldToAskAdmin(t *testing.T) {
	fixture := newRouteTestFixture(t, true)
	fixture.server.multiUserService.SetABSUserLister(routeABSUsers{})
	member := newRouteSession(t, fixture, "no-abs-account", auth.RoleUser)
	admin := loginRouteAdmin(t, fixture)

	response := fixture.requestWithCookies(http.MethodPost, "/api/profiles", []byte(`{
		"id": "orphan", "name": "orphan",
		"audiobookshelf_url": "http://audiobookshelf.invalid",
		"audiobookshelf_token": "t", "hardcover_token": "h", "sync_config": {}
	}`), []*http.Cookie{member.cookie})
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	created := decodeLinkEnvelope(t, response.Body.Bytes())
	require.Equal(t, map[string]interface{}{"state": "none"}, created.Data["abs_link"])
	require.Contains(t, created.Data["abs_link_error"], "No Audiobookshelf account matches")

	response = fixture.requestWithCookies(http.MethodPost, "/api/profiles/orphan/abs-link", nil, []*http.Cookie{member.cookie})
	require.Equal(t, http.StatusUnprocessableEntity, response.Code, response.Body.String())

	// The admin links it by hand to a chosen user: approved at once.
	fixture.server.multiUserService.SetABSUserLister(routeABSUsers{users: []audiobookshelf.UserSummary{
		{ID: "abs-renamed", Username: "old-name", HasOpenIDLink: true, IsActive: true},
	}})
	response = fixture.requestWithCookies(http.MethodGet, "/api/admin/abs-users", nil, []*http.Cookie{admin.cookie})
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), `"username":"old-name"`)

	response = fixture.requestWithCookies(http.MethodPut, "/api/admin/profiles/orphan/abs-link",
		[]byte(`{"abs_user_id":"abs-renamed"}`), []*http.Cookie{admin.cookie})
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Equal(t, "approved", decodeLinkEnvelope(t, response.Body.Bytes()).Data["state"])
}

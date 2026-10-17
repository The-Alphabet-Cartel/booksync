package multiuser

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/database"
	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/hardcoveroauth"
)

// Booksync F3 tests: connecting, refreshing and disconnecting Hardcover.

type fakeHardcoverOAuth struct {
	*httptest.Server
	rotate        bool
	rejectRefresh bool
	revokeStatus  int
	revoked       []string
}

func newFakeHardcoverOAuth(t *testing.T) *fakeHardcoverOAuth {
	t.Helper()
	f := &fakeHardcoverOAuth{revokeStatus: http.StatusOK}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth2/token":
			switch r.Form.Get("grant_type") {
			case "authorization_code":
				if r.Form.Get("code") != "good-code" || r.Form.Get("code_verifier") == "" {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
					return
				}
				_, _ = w.Write([]byte(`{"access_token":"hc_at_member","refresh_token":"hc_rt_member","token_type":"Bearer","expires_in":3600}`))
			case "refresh_token":
				if f.rejectRefresh {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
					return
				}
				body := map[string]interface{}{"access_token": "hc_at_refreshed", "token_type": "Bearer", "expires_in": 3600}
				if f.rotate {
					body["refresh_token"] = "hc_rt_rotated"
				}
				_ = json.NewEncoder(w).Encode(body)
			}
		case "/oauth2/revoke":
			f.revoked = append(f.revoked, r.Form.Get("token"))
			w.WriteHeader(f.revokeStatus)
		case "/v1/graphql":
			_, _ = w.Write([]byte(`{"data":{"me":[{"username":"member-on-hardcover"}]}}`))
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeHardcoverOAuth) config() hardcoveroauth.Config {
	return hardcoveroauth.Config{
		ClientID: "client", ClientSecret: "secret", RedirectURL: "https://booksync.invalid/auth/hardcover/callback",
		TokenURL: f.URL + "/oauth2/token", RevokeURL: f.URL + "/oauth2/revoke", APIURL: f.URL + "/v1/graphql",
	}
}

func newHardcoverService(t *testing.T) (*MultiUserService, *gorm.DB, *fakeHardcoverOAuth) {
	t.Helper()
	service, db := newStatusLookupService(t)
	fake := newFakeHardcoverOAuth(t)
	service.SetHardcoverOAuthConfig(fake.config())
	t.Cleanup(func() { require.NoError(t, service.Shutdown(context.Background())) })
	return service, db, fake
}

func callbackQuery(t *testing.T, authURL, code, iss string) url.Values {
	t.Helper()
	u, err := url.Parse(authURL)
	require.NoError(t, err)
	q := url.Values{"state": {u.Query().Get("state")}, "code": {code}}
	if iss != "" {
		q.Set("iss", iss)
	}
	return q
}

func connectHardcover(t *testing.T, service *MultiUserService, profileID, userID string) {
	t.Helper()
	authURL, err := service.BeginHardcoverConnect(profileID, userID)
	require.NoError(t, err)
	_, _, err = service.CompleteHardcoverConnect(context.Background(), userID, callbackQuery(t, authURL, "good-code", hardcoveroauth.Issuer))
	require.NoError(t, err)
}

func TestHardcoverConnectStoresEncryptedTokenAndUsername(t *testing.T) {
	service, db, _ := newHardcoverService(t)
	createOwnedProfile(t, service, "member", "owner-member")

	authURL, err := service.BeginHardcoverConnect("member", "owner-member")
	require.NoError(t, err)
	u, err := url.Parse(authURL)
	require.NoError(t, err)
	require.Equal(t, "hardcover.app", u.Host)
	require.Equal(t, "S256", u.Query().Get("code_challenge_method"))

	profileID, conn, err := service.CompleteHardcoverConnect(context.Background(), "owner-member",
		callbackQuery(t, authURL, "good-code", hardcoveroauth.Issuer))
	require.NoError(t, err)
	require.Equal(t, "member", profileID)
	require.Equal(t, &HardcoverConnection{State: database.HardcoverStateConnected, Username: "member-on-hardcover"}, conn)

	profile, err := service.GetProfile("member")
	require.NoError(t, err)
	require.Equal(t, database.HardcoverStateConnected, profile.Profile.HardcoverState)
	require.Equal(t, "member-on-hardcover", profile.Profile.HardcoverUsername)
	token, err := hardcoveroauth.DecodeToken(profile.HardcoverToken)
	require.NoError(t, err)
	require.Equal(t, "hc_at_member", token.AccessToken)
	require.Equal(t, "hc_rt_member", token.RefreshToken)

	// What is actually on disk is ciphertext.
	var raw string
	require.NoError(t, db.Raw("SELECT hardcover_token_encrypted FROM sync_profile_configs WHERE profile_id = ?", "member").Scan(&raw).Error)
	require.NotEmpty(t, raw)
	require.NotContains(t, raw, "hc_at_member")
	require.NotContains(t, raw, "hc_rt_member")
}

func TestHardcoverConnectRefusals(t *testing.T) {
	service, _, _ := newHardcoverService(t)
	createOwnedProfile(t, service, "member", "owner-member")

	_, err := service.BeginHardcoverConnect("member", "someone-else")
	require.ErrorIs(t, err, ErrHardcoverNotOwner)
	_, err = service.BeginHardcoverConnect("missing", "owner-member")
	require.ErrorIs(t, err, ErrProfileNotFound)

	authURL, err := service.BeginHardcoverConnect("member", "owner-member")
	require.NoError(t, err)
	_, _, err = service.CompleteHardcoverConnect(context.Background(), "owner-member", callbackQuery(t, authURL, "good-code", ""))
	require.ErrorIs(t, err, hardcoveroauth.ErrIssuer)
	// The failed callback spent the state: replaying it with a good iss fails.
	_, _, err = service.CompleteHardcoverConnect(context.Background(), "owner-member", callbackQuery(t, authURL, "good-code", hardcoveroauth.Issuer))
	require.ErrorIs(t, err, hardcoveroauth.ErrStateUnknown)

	authURL, err = service.BeginHardcoverConnect("member", "owner-member")
	require.NoError(t, err)
	_, _, err = service.CompleteHardcoverConnect(context.Background(), "intruder", callbackQuery(t, authURL, "good-code", hardcoveroauth.Issuer))
	require.ErrorIs(t, err, hardcoveroauth.ErrStateUser)

	authURL, err = service.BeginHardcoverConnect("member", "owner-member")
	require.NoError(t, err)
	_, _, err = service.CompleteHardcoverConnect(context.Background(), "owner-member", callbackQuery(t, authURL, "bad-code", hardcoveroauth.Issuer))
	require.Error(t, err)

	profile, err := service.GetProfileMetadata("member")
	require.NoError(t, err)
	require.Equal(t, database.HardcoverStateNone, database.NormalizeHardcoverState(profile.HardcoverState))

	unconfigured, _ := newStatusLookupService(t)
	createOwnedProfile(t, unconfigured, "member", "owner-member")
	_, err = unconfigured.BeginHardcoverConnect("member", "owner-member")
	require.ErrorIs(t, err, hardcoveroauth.ErrNotConfigured)
}

func TestSyncGateNeedsConnectedHardcover(t *testing.T) {
	service, _, _ := newHardcoverService(t)
	service.SetABSUserLister(&fakeABSUsers{users: nil})
	createOwnedProfile(t, service, "member", "owner-member")
	require.NoError(t, service.repository.SetABSLink("member", "abs-member", "member", database.ABSLinkStateApproved))

	_, err := service.StartSyncWithAcceptedRun("member")
	require.ErrorIs(t, err, ErrHardcoverNotConnected)

	connectHardcover(t, service, "member", "owner-member")
	_, err = service.StartSyncWithAcceptedRun("member")
	require.False(t, errors.Is(err, ErrHardcoverNotConnected), "connected profile was refused: %v", err)
	waitForSyncs(service)
}

func storeExpiredToken(t *testing.T, service *MultiUserService, profileID string) {
	t.Helper()
	require.NoError(t, service.repository.SetHardcoverConnection(profileID,
		`{"access_token":"hc_at_old","refresh_token":"hc_rt_member","expiry":"`+time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)+`"}`,
		"member-on-hardcover"))
}

func TestRefreshSavesRotatedToken(t *testing.T) {
	service, _, fake := newHardcoverService(t)
	fake.rotate = true
	createOwnedProfile(t, service, "member", "owner-member")
	storeExpiredToken(t, service, "member")
	profile, err := service.GetProfile("member")
	require.NoError(t, err)

	tokenFunc, err := service.hardcoverTokenFunc(context.Background(), "member", profile.HardcoverToken)
	require.NoError(t, err)
	access, err := tokenFunc()
	require.NoError(t, err)
	require.Equal(t, "hc_at_refreshed", access)

	profile, err = service.GetProfile("member")
	require.NoError(t, err)
	saved, err := hardcoveroauth.DecodeToken(profile.HardcoverToken)
	require.NoError(t, err)
	require.Equal(t, "hc_at_refreshed", saved.AccessToken)
	require.Equal(t, "hc_rt_rotated", saved.RefreshToken)
}

func TestRefusedRefreshMarksNeedsReconnectAndGateRefuses(t *testing.T) {
	service, _, fake := newHardcoverService(t)
	fake.rejectRefresh = true
	createOwnedProfile(t, service, "member", "owner-member")
	require.NoError(t, service.repository.SetABSLink("member", "abs-member", "member", database.ABSLinkStateApproved))
	storeExpiredToken(t, service, "member")
	profile, err := service.GetProfile("member")
	require.NoError(t, err)

	tokenFunc, err := service.hardcoverTokenFunc(context.Background(), "member", profile.HardcoverToken)
	require.NoError(t, err)
	_, err = tokenFunc()
	require.ErrorIs(t, err, hardcoveroauth.ErrReconnectRequired)

	meta, err := service.GetProfileMetadata("member")
	require.NoError(t, err)
	require.Equal(t, database.HardcoverStateNeedsReconnect, meta.HardcoverState)
	_, err = service.StartSyncWithAcceptedRun("member")
	require.ErrorIs(t, err, ErrHardcoverNotConnected)
}

func TestDisconnectRevokesThenDeletesEvenWhenRevokeFails(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			service, _, fake := newHardcoverService(t)
			fake.revokeStatus = status
			createOwnedProfile(t, service, "member", "owner-member")
			connectHardcover(t, service, "member", "owner-member")

			revokeErr, err := service.DisconnectHardcover(context.Background(), "member")
			require.NoError(t, err)
			require.Equal(t, []string{"hc_rt_member"}, fake.revoked)
			if status == http.StatusOK {
				require.NoError(t, revokeErr)
			} else {
				require.Error(t, revokeErr)
			}

			profile, err := service.GetProfile("member")
			require.NoError(t, err)
			require.Empty(t, profile.HardcoverToken)
			require.Equal(t, database.HardcoverStateNone, profile.Profile.HardcoverState)
			require.Empty(t, profile.Profile.HardcoverUsername)
		})
	}
}

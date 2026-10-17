package multiuser

// Booksync F4: booksync mode -- every sync reads the member's progress through
// the server-held Audiobookshelf admin key and an approved link.

import (
	"net/http"
	"net/http/httptest"
	gosync "sync"
	"testing"

	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/database"
	"github.com/stretchr/testify/require"
)

// newBooksyncService is the Hardcover test service switched to booksync mode
// (TestPerProfileABS off), with the given server-level ABS settings.
func newBooksyncService(t *testing.T, absURL, absKey string) *MultiUserService {
	t.Helper()
	service, _, _ := newHardcoverService(t)
	service.globalConfig.TestPerProfileABS = false
	service.globalConfig.Audiobookshelf.URL = absURL
	service.globalConfig.Audiobookshelf.Token = absKey
	// Fail fast instead of reaching the real Hardcover API.
	service.globalConfig.Hardcover.BaseURL = "http://127.0.0.1:1"
	return service
}

// readyMemberProfile creates an owned profile with no member ABS settings, an
// approved link to absUserID and a connected Hardcover account.
func readyMemberProfile(t *testing.T, service *MultiUserService, profileID, ownerID, absUserID string) {
	t.Helper()
	require.NoError(t, service.repository.CreateProfileForUser(
		profileID, profileID, "", "", "", database.SyncConfigData{DryRun: true}, ownerID,
	))
	require.NoError(t, service.repository.SetABSLink(profileID, absUserID, profileID, database.ABSLinkStateApproved))
	connectHardcover(t, service, profileID, ownerID)
}

func TestBooksyncModeWithoutAdminKeyRefusesEverySync(t *testing.T) {
	service := newBooksyncService(t, "http://abs.invalid", "")
	readyMemberProfile(t, service, "member", "owner-member", "abs-member")

	_, err := service.StartSyncWithAcceptedRun("member")
	require.ErrorIs(t, err, ErrABSNotConfigured)
	require.Contains(t, err.Error(), "Audiobookshelf admin key not configured")
	require.False(t, service.ABSAdminConfigured())
}

func TestBooksyncModeRefusesOwnerlessAndUnlinkedProfiles(t *testing.T) {
	service := newBooksyncService(t, "http://abs.invalid", "admin-key")
	require.NoError(t, service.repository.CreateProfile(
		"legacy", "Legacy", "", "", "", database.SyncConfigData{DryRun: true},
	))
	_, err := service.StartSyncWithAcceptedRun("legacy")
	require.ErrorIs(t, err, ErrProfileNotApproved)

	require.NoError(t, service.repository.CreateProfileForUser(
		"unlinked", "Unlinked", "", "", "", database.SyncConfigData{DryRun: true}, "owner-u",
	))
	_, err = service.StartSyncWithAcceptedRun("unlinked")
	require.ErrorIs(t, err, ErrProfileNotApproved)
}

func TestBooksyncModeRefusesMemberABSSettings(t *testing.T) {
	service := newBooksyncService(t, "http://abs.invalid", "admin-key")

	err := service.CreateProfileForUser("p1", "P1", "https://evil.example", "", "", database.SyncConfigData{}, "owner")
	require.ErrorIs(t, err, ErrABSSettingsServerManaged)
	err = service.CreateProfileForUser("p1", "P1", "", "member-token", "", database.SyncConfigData{}, "owner")
	require.ErrorIs(t, err, ErrABSSettingsServerManaged)
	profile, err := service.GetProfile("p1")
	require.True(t, profile == nil || err != nil, "a refused create must store nothing")

	require.NoError(t, service.CreateProfileForUser("p2", "P2", "", "", "", database.SyncConfigData{}, "owner"))
	err = service.UpdateProfileConfig("p2", "https://evil.example", "", "", database.SyncConfigData{})
	require.ErrorIs(t, err, ErrABSSettingsServerManaged)
	stored, err := service.GetProfile("p2")
	require.NoError(t, err)
	require.Empty(t, stored.AudiobookshelfURL)
	require.Empty(t, stored.AudiobookshelfToken)
}

func TestBooksyncModeSyncReadsTheLinkedUserThroughTheAdminKey(t *testing.T) {
	var mu gosync.Mutex
	type hit struct{ path, query, auth string }
	var hits []hit
	abs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, hit{r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization")})
		mu.Unlock()
		switch r.URL.Path {
		case "/api/users/abs-member":
			_, _ = w.Write([]byte(`{"id":"abs-member","username":"member","mediaProgress":[]}`))
		case "/api/libraries":
			_, _ = w.Write([]byte(`{"libraries":[{"id":"lib1","name":"Books"}]}`))
		case "/api/libraries/lib1/items":
			_, _ = w.Write([]byte(`{"results":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer abs.Close()

	service := newBooksyncService(t, abs.URL, "admin-key")
	readyMemberProfile(t, service, "member", "owner-member", "abs-member")

	_, err := service.StartSyncWithAcceptedRun("member")
	require.NoError(t, err)
	waitForSyncs(service)

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, hits, "the sync never reached Audiobookshelf")
	sawUser := false
	for _, h := range hits {
		require.Equal(t, "Bearer admin-key", h.auth, "every ABS call uses the server-held key")
		require.NotEqual(t, "/api/me", h.path, "booksync mode must never read the key's own user")
		require.NotContains(t, h.query, "include=progress")
		if h.path == "/api/users/abs-member" {
			sawUser = true
		}
	}
	require.True(t, sawUser, "progress was not read from /api/users/{id}: %+v", hits)
}

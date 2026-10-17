package server

// Booksync F4: in booksync mode the dashboard API refuses member-supplied
// Audiobookshelf settings and reports a missing admin key on sync start.

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/auth"
	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/config"
	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/crypto"
	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/database"
	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/logger"
	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/multiuser"
	"github.com/stretchr/testify/require"
)

// newBooksyncRouteFixture is newRouteTestFixtureWithHardcoverURL without the
// test-only per-profile switch, and with no server-level ABS admin key.
func newBooksyncRouteFixture(t *testing.T) *routeTestFixture {
	t.Helper()
	logger.ForceSetup(logger.Config{Level: "error", Format: logger.FormatJSON, Output: io.Discard})
	dataDir := t.TempDir()
	db, err := database.NewDatabase(&database.DatabaseConfig{
		Type: database.DatabaseTypeSQLite,
		Path: filepath.Join(dataDir, "server-booksync-test.db"),
	}, logger.Get())
	require.NoError(t, err)
	encryptor, err := crypto.NewEncryptionManagerWithDataDir(dataDir, logger.Get())
	require.NoError(t, err)
	repo := database.NewRepository(db, encryptor, logger.Get())
	cfg := config.DefaultConfig()
	cfg.Paths.DataDir = dataDir
	cfg.Audiobookshelf.URL = "http://abs.invalid"
	cfg.Audiobookshelf.Token = ""
	cfg.RateLimit.Rate = time.Nanosecond
	cfg.RateLimit.MaxConcurrent = 1
	multiUserService := multiuser.NewMultiUserService(repo, cfg, logger.Get())
	authConfig := auth.DefaultAuthConfig()
	authConfig.Enabled = true
	authService, err := auth.NewAuthService(db.GetDB(), authConfig, logger.Get())
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, multiUserService.Shutdown(context.Background()))
		require.NoError(t, db.Close())
	})
	return &routeTestFixture{dataDir: dataDir, repo: repo, server: New("", multiUserService, authService, logger.Get())}
}

func TestBooksyncRoutesRefuseMemberABSSettings(t *testing.T) {
	fixture := newBooksyncRouteFixture(t)
	member := newRouteSession(t, fixture, "member", auth.RoleUser)
	cookies := []*http.Cookie{member.cookie}

	for _, body := range []string{
		`{"id":"p1","name":"P1","audiobookshelf_url":"https://evil.example","sync_config":{"dry_run":true}}`,
		`{"id":"p1","name":"P1","audiobookshelf_token":"member-abs-token","sync_config":{"dry_run":true}}`,
	} {
		response := fixture.requestWithCookies(http.MethodPost, "/api/profiles", []byte(body), cookies)
		require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
		require.Contains(t, response.Body.String(), "Audiobookshelf settings are managed by the server")
	}
	stored, err := fixture.repo.GetProfile("p1")
	require.True(t, stored == nil || err != nil, "a refused create must store nothing")

	// Without ABS fields the create succeeds.
	response := fixture.requestWithCookies(http.MethodPost, "/api/profiles",
		[]byte(`{"id":"p2","name":"P2","sync_config":{"dry_run":true}}`), cookies)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())

	// A config update carrying a token is refused and changes nothing.
	response = fixture.requestWithCookies(http.MethodPut, "/api/profiles/p2/config",
		[]byte(`{"audiobookshelf_token":"member-abs-token"}`), cookies)
	require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
	stored, err = fixture.repo.GetProfile("p2")
	require.NoError(t, err)
	require.Empty(t, stored.AudiobookshelfToken)
	require.False(t, strings.Contains(stored.AudiobookshelfURL, "evil"))
}

func TestBooksyncRoutesSyncStartReportsMissingAdminKey(t *testing.T) {
	fixture := newBooksyncRouteFixture(t)
	member := newRouteSession(t, fixture, "member", auth.RoleUser)
	cookies := []*http.Cookie{member.cookie}
	response := fixture.requestWithCookies(http.MethodPost, "/api/profiles",
		[]byte(`{"id":"p3","name":"P3","sync_config":{"dry_run":true}}`), cookies)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())

	response = fixture.requestWithCookies(http.MethodPost, "/api/profiles/p3/sync", nil, cookies)
	require.Equal(t, http.StatusServiceUnavailable, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), "Audiobookshelf admin key not configured")
}

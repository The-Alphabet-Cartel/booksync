package audiobookshelf

// Booksync F4: reading one member's progress through the server-held admin
// key, and never logging or dumping Audiobookshelf response bodies.

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/logger"
	"github.com/stretchr/testify/require"
)

func TestNewClientForUserReadsThatUserThroughTheAdminKey(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.EscapedPath(), r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"id":"abs/1","username":"alice","token":"member-legacy-token","mediaProgress":[{"id":"p1","libraryItemId":"li1","progress":0.5,"currentTime":120}]}`))
	}))
	defer srv.Close()

	progress, err := NewClientForUser(srv.URL, "admin-key", "abs/1").GetUserProgress(context.Background())
	require.NoError(t, err)
	require.Equal(t, "/api/users/abs%2F1", gotPath)
	require.Equal(t, "Bearer admin-key", gotAuth)
	require.Equal(t, "abs/1", progress.ID)
	require.Len(t, progress.MediaProgress, 1)

	// Upstream's client still reads the key's own user.
	_, err = NewClient(srv.URL, "own-key").GetUserProgress(context.Background())
	require.NoError(t, err)
	require.Equal(t, "/api/me", gotPath)
}

// captureLogs routes the global logger into a buffer for one test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var mu sync.Mutex
	buf := &bytes.Buffer{}
	logger.ForceSetup(logger.Config{Level: "debug", Format: logger.FormatJSON, Output: lockedWriter{&mu, buf}})
	t.Cleanup(func() { logger.ForceSetup(logger.Config{Level: "error", Format: logger.FormatJSON, Output: os.Stderr}) })
	return buf
}

type lockedWriter struct {
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func TestErrorResponsesNeverReachLogsOrErrors(t *testing.T) {
	const secret = "body-secret-token-f4"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"` + secret + `"}`))
	}))
	defer srv.Close()
	logs := captureLogs(t)

	c := NewClientForUser(srv.URL, "admin-key", "abs-1")
	_, err1 := c.GetUserProgress(context.Background())
	_, err2 := c.GetLibraries(context.Background())
	_, err3 := c.GetLibraryItems(context.Background(), "lib1")
	_, err4 := c.GetListeningSessions(context.Background(), time.Time{})
	for _, err := range []error{err1, err2, err3, err4} {
		require.Error(t, err)
		require.NotContains(t, err.Error(), secret)
	}
	require.Contains(t, logs.String(), "Unexpected status code", "the failures should still be logged")
	require.NotContains(t, logs.String(), secret)
}

func TestGetLibraryItemsDropsIncludeProgressAndWritesNoFiles(t *testing.T) {
	const marker = "item-body-marker-f4"
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		// The marker sits in a field the client never decodes, so only a
		// raw-body log or dump could carry it.
		_, _ = w.Write([]byte(`{"results":[{"id":"li1","undecoded":"` + marker + `","media":{"metadata":{"title":"T"}}}]}`))
	}))
	defer srv.Close()
	logs := captureLogs(t)

	tmpRaw := "/tmp/audiobookshelf_raw_response.json"
	tmpFallback := filepath.Join(os.TempDir(), "audiobookshelf_response.json")
	_ = os.Remove(tmpRaw)
	_ = os.Remove(tmpFallback)
	t.Chdir(t.TempDir())

	items, err := NewClientForUser(srv.URL, "admin-key", "abs-1").GetLibraryItems(context.Background(), "lib1")
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, "minified=0", gotQuery)
	require.False(t, strings.Contains(gotQuery, "include"), "include=progress would describe the key owner, not the member")

	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	require.Empty(t, entries, "no raw response files or logs directory in the working directory")
	for _, p := range []string{tmpRaw, tmpFallback} {
		_, err := os.Stat(p)
		require.True(t, os.IsNotExist(err), "unexpected raw response dump at %s", p)
	}
	require.NotContains(t, logs.String(), marker, "response bodies must not be logged")
}

package hardcover

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Booksync F3: the client asks its token source on every request, so an
// OAuth access token refreshed mid-sync is used at once, and a refused
// refresh stops the request instead of sending an empty token.
func TestClientWithTokenSourceUsesFreshTokenPerRequest(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"me":[{"id":7}]}}`))
	}))
	defer server.Close()

	cfg := DefaultClientConfig()
	cfg.BaseURL = server.URL
	cfg.RateLimit = time.Nanosecond
	cfg.MaxRetries = 0
	tokens := []string{"hc_at_first", "hc_at_second"}
	calls := 0
	client := NewClientWithTokenSource(cfg, func() (string, error) {
		token := tokens[calls]
		calls++
		return token, nil
	}, nil)

	var resp map[string]interface{}
	require.NoError(t, client.GraphQLQuery(context.Background(), "query A { me { id } }", nil, &resp))
	require.NoError(t, client.GraphQLQuery(context.Background(), "query B { me { id } }", nil, &resp))
	require.Equal(t, []string{"Bearer hc_at_first", "Bearer hc_at_second"}, seen)
}

func TestClientWithTokenSourceStopsWhenTokenRefused(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer server.Close()

	cfg := DefaultClientConfig()
	cfg.BaseURL = server.URL
	cfg.RateLimit = time.Nanosecond
	refused := errors.New("hardcover connection must be renewed")
	client := NewClientWithTokenSource(cfg, func() (string, error) { return "", refused }, nil)

	var resp map[string]interface{}
	err := client.GraphQLQuery(context.Background(), "query { me { id } }", nil, &resp)
	require.ErrorIs(t, err, refused)
	require.Zero(t, hits, "no request may go out without a token")
}

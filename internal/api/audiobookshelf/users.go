package audiobookshelf

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Booksync F2: listing Audiobookshelf users through the server-held admin key.

// maxUsersResponseBytes caps how much of GET /api/users is read. A few
// hundred users is far below this.
const maxUsersResponseBytes = 8 << 20

// UserSummary is the only part of an Audiobookshelf user booksync keeps.
//
// GET /api/users returns every non-root user's legacy API token to an admin
// key. Decoding into this struct drops it: the token never reaches a Go
// value, and the response body is never logged or written anywhere.
type UserSummary struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	HasOpenIDLink bool   `json:"hasOpenIDLink"`
	IsActive      bool   `json:"isActive"`
}

// ListUsers returns every Audiobookshelf user as a UserSummary. It needs an
// admin key.
func (c *Client) ListUsers(ctx context.Context) ([]UserSummary, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+apiPath+"/users", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// The status alone: an error body could echo request details.
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return decodeUserSummaries(io.LimitReader(resp.Body, maxUsersResponseBytes))
}

func decodeUserSummaries(body io.Reader) ([]UserSummary, error) {
	var result struct {
		Users []UserSummary `json:"users"`
	}
	if err := json.NewDecoder(body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode users response: %w", err)
	}
	if result.Users == nil {
		return nil, fmt.Errorf("users response has no users list")
	}
	return result.Users, nil
}

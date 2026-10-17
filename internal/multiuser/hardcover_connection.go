package multiuser

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	stdSync "sync"

	"golang.org/x/oauth2"

	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/database"
	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/hardcoveroauth"
)

// Booksync F3: connecting, refreshing and disconnecting a member's Hardcover
// account through OAuth. Members never paste a token.

// ErrHardcoverNotConnected means an owned profile has no usable Hardcover
// connection (never connected, disconnected, or Hardcover refused a refresh).
var ErrHardcoverNotConnected = errors.New("hardcover not connected")

// ErrHardcoverNotOwner means the caller does not own the profile. A member's
// Hardcover account can only be connected by that member.
var ErrHardcoverNotOwner = errors.New("only the profile owner can connect Hardcover")

// HardcoverConnection is a profile's Hardcover state as shown to its owner.
type HardcoverConnection struct {
	State    string `json:"state"`
	Username string `json:"username,omitempty"`
}

type hardcoverOAuthState struct {
	once   stdSync.Once
	states *hardcoveroauth.StateStore
	config *hardcoveroauth.Config // test override
}

// SetHardcoverOAuthConfig replaces the OAuth client configuration. Production
// code never calls it; tests point it at a fake Hardcover.
func (s *MultiUserService) SetHardcoverOAuthConfig(cfg hardcoveroauth.Config) {
	s.hardcover.config = &cfg
}

func (s *MultiUserService) hardcoverStates() *hardcoveroauth.StateStore {
	s.hardcover.once.Do(func() { s.hardcover.states = hardcoveroauth.NewStateStore() })
	return s.hardcover.states
}

func (s *MultiUserService) hardcoverOAuthConfig() (hardcoveroauth.Config, error) {
	if s.hardcover.config != nil {
		return *s.hardcover.config, nil
	}
	if s.globalConfig == nil {
		return hardcoveroauth.Config{}, hardcoveroauth.ErrNotConfigured
	}
	cfg := hardcoveroauth.Config{
		ClientID:     s.globalConfig.Hardcover.OAuthClientID,
		ClientSecret: s.globalConfig.Hardcover.OAuthClientSecret,
		RedirectURL:  s.globalConfig.Hardcover.OAuthRedirectURL,
		APIURL:       s.globalConfig.Hardcover.BaseURL,
	}
	if !cfg.Enabled() {
		return hardcoveroauth.Config{}, hardcoveroauth.ErrNotConfigured
	}
	return cfg, nil
}

func connectionFromProfile(profile *database.SyncProfile) *HardcoverConnection {
	return &HardcoverConnection{
		State:    database.NormalizeHardcoverState(profile.HardcoverState),
		Username: profile.HardcoverUsername,
	}
}

// BeginHardcoverConnect returns the Hardcover URL the owner's browser is sent
// to. The state and PKCE verifier stay server-side for StateTTL.
func (s *MultiUserService) BeginHardcoverConnect(profileID, userID string) (string, error) {
	cfg, err := s.hardcoverOAuthConfig()
	if err != nil {
		return "", err
	}
	profile, err := s.repository.GetProfileMetadata(profileID)
	if err != nil {
		return "", err
	}
	if profile == nil {
		return "", ErrProfileNotFound
	}
	if profile.OwnerUserID == nil || *profile.OwnerUserID != userID {
		return "", ErrHardcoverNotOwner
	}
	state, verifier := s.hardcoverStates().Begin(profileID, userID)
	return cfg.AuthCodeURL(state, verifier), nil
}

// CompleteHardcoverConnect handles Hardcover's callback for the signed-in
// user and stores the token set. It returns the profile it connected.
func (s *MultiUserService) CompleteHardcoverConnect(ctx context.Context, userID string, query url.Values) (string, *HardcoverConnection, error) {
	cfg, err := s.hardcoverOAuthConfig()
	if err != nil {
		return "", nil, err
	}
	code, state, err := hardcoveroauth.CheckCallback(query)
	if err != nil {
		if state := query.Get("state"); state != "" {
			_, _ = s.hardcoverStates().Take(state, userID) // spend it
		}
		return "", nil, err
	}
	pending, err := s.hardcoverStates().Take(state, userID)
	if err != nil {
		return "", nil, err
	}
	profile, err := s.repository.GetProfileMetadata(pending.ProfileID)
	if err != nil {
		return "", nil, err
	}
	if profile == nil {
		return "", nil, ErrProfileNotFound
	}
	if profile.OwnerUserID == nil || *profile.OwnerUserID != userID {
		return "", nil, ErrHardcoverNotOwner
	}
	token, err := cfg.Exchange(ctx, code, pending.Verifier)
	if err != nil {
		return "", nil, fmt.Errorf("hardcover code exchange failed: %w", err)
	}
	encoded, err := hardcoveroauth.EncodeToken(token)
	if err != nil {
		return "", nil, err
	}
	username, err := cfg.FetchUsername(ctx, token.AccessToken)
	if err != nil {
		// The connection works without a display name.
		s.logger.Warn("Hardcover connected but its username could not be read", map[string]interface{}{
			"profile_id": pending.ProfileID,
			"error":      err.Error(),
		})
		username = ""
	}
	if err := s.repository.SetHardcoverConnection(pending.ProfileID, encoded, username); err != nil {
		return "", nil, err
	}
	s.logger.Info("Hardcover connected", map[string]interface{}{
		"profile_id":         pending.ProfileID,
		"hardcover_username": username,
	})
	return pending.ProfileID, &HardcoverConnection{State: database.HardcoverStateConnected, Username: username}, nil
}

// DisconnectHardcover revokes the token at Hardcover, then deletes it locally
// whatever Hardcover answered. revokeErr reports a failed revocation so the
// member can remove booksync from Hardcover's Authorized Apps themselves.
func (s *MultiUserService) DisconnectHardcover(ctx context.Context, profileID string) (revokeErr error, err error) {
	profileConfig, err := s.repository.GetProfile(profileID)
	if err != nil {
		return nil, err
	}
	if profileConfig == nil {
		return nil, ErrProfileNotFound
	}
	if token, decodeErr := hardcoveroauth.DecodeToken(profileConfig.HardcoverToken); decodeErr == nil {
		if cfg, cfgErr := s.hardcoverOAuthConfig(); cfgErr != nil {
			revokeErr = cfgErr
		} else if token.RefreshToken != "" {
			revokeErr = cfg.Revoke(ctx, token.RefreshToken, "refresh_token")
		} else {
			revokeErr = cfg.Revoke(ctx, token.AccessToken, "access_token")
		}
	}
	if err := s.repository.ClearHardcoverConnection(profileID); err != nil {
		return revokeErr, err
	}
	if revokeErr != nil {
		s.logger.Warn("Hardcover token deleted locally but revocation failed", map[string]interface{}{
			"profile_id": profileID,
			"error":      revokeErr.Error(),
		})
	}
	return revokeErr, nil
}

// hardcoverTokenFunc builds the per-request token source for a connected
// profile's sync: it refreshes, saves rotated tokens, and on a refused refresh
// marks the profile needs_reconnect once.
func (s *MultiUserService) hardcoverTokenFunc(ctx context.Context, profileID, stored string) (func() (string, error), error) {
	cfg, err := s.hardcoverOAuthConfig()
	if err != nil {
		return nil, err
	}
	token, err := hardcoveroauth.DecodeToken(stored)
	if err != nil {
		return nil, err
	}
	source := cfg.TokenSource(ctx, token,
		func(t *oauth2.Token) error {
			encoded, err := hardcoveroauth.EncodeToken(t)
			if err != nil {
				return err
			}
			return s.repository.UpdateHardcoverToken(profileID, encoded)
		},
		func() {
			if err := s.repository.SetHardcoverState(profileID, database.HardcoverStateNeedsReconnect); err != nil {
				s.logger.Error("Failed to mark Hardcover reconnect needed", map[string]interface{}{
					"profile_id": profileID,
					"error":      err.Error(),
				})
				return
			}
			s.logger.Warn("Hardcover refused the refresh token; the member must reconnect", map[string]interface{}{
				"profile_id": profileID,
			})
		})
	return func() (string, error) {
		t, err := source.Token()
		if err != nil {
			return "", err
		}
		return t.AccessToken, nil
	}, nil
}

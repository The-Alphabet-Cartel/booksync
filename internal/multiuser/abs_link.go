package multiuser

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/api/audiobookshelf"
	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/database"
)

// Booksync F2: linking a member's profile to their Audiobookshelf user.
//
// Audiobookshelf never exposes the OIDC subject, so the member's username is
// the only key. Pocket ID lets members rename themselves, which frees old
// usernames for someone else to take, so a match is never trusted on its own:
// it is held as pending until an admin approves it, and an owned profile does
// not sync until then (see StartSyncWithAcceptedRun).

// ErrABSUserNotFound means no active, OIDC-linked Audiobookshelf user has the
// member's username.
var ErrABSUserNotFound = errors.New("no matching audiobookshelf user")

// ErrABSUserAmbiguous means more than one active, OIDC-linked Audiobookshelf
// user has the member's username. Audiobookshelf does not enforce unique
// usernames, so this can happen.
var ErrABSUserAmbiguous = errors.New("more than one matching audiobookshelf user")

// ErrABSNotConfigured means the server-level Audiobookshelf URL or admin key
// is missing.
var ErrABSNotConfigured = errors.New("Audiobookshelf admin key not configured")

// ErrABSLinkNotOwner means the caller does not own the profile. Only the owner
// can ask for their own profile to be matched; admins re-link by hand.
var ErrABSLinkNotOwner = errors.New("only the profile owner can link it")

// absLookupTimeout bounds one Audiobookshelf user listing.
const absLookupTimeout = 15 * time.Second

// ABSUserLister lists Audiobookshelf users. *audiobookshelf.Client satisfies
// it; tests substitute a fake.
type ABSUserLister interface {
	ListUsers(ctx context.Context) ([]audiobookshelf.UserSummary, error)
}

// ABSLink is a profile's link as reported to its owner and to admins.
type ABSLink struct {
	State       string `json:"state"`
	ABSUsername string `json:"abs_username,omitempty"`
}

// ABSUserOption is one Audiobookshelf user offered to an admin for a manual
// re-link. It never carries anything beyond these fields.
type ABSUserOption struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	HasOpenIDLink bool   `json:"has_openid_link"`
}

// SetABSUserLister replaces the Audiobookshelf user source. Production code
// never calls it; it exists so tests do not need a live Audiobookshelf.
func (s *MultiUserService) SetABSUserLister(lister ABSUserLister) {
	s.absUsers = lister
}

func (s *MultiUserService) absUserLister() (ABSUserLister, error) {
	if s.absUsers != nil {
		return s.absUsers, nil
	}
	if s.globalConfig == nil || s.globalConfig.Audiobookshelf.URL == "" || s.globalConfig.Audiobookshelf.Token == "" {
		return nil, ErrABSNotConfigured
	}
	return audiobookshelf.NewClient(s.globalConfig.Audiobookshelf.URL, s.globalConfig.Audiobookshelf.Token), nil
}

func (s *MultiUserService) listABSUsers(ctx context.Context) ([]audiobookshelf.UserSummary, error) {
	lister, err := s.absUserLister()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, absLookupTimeout)
	defer cancel()
	users, err := lister.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list audiobookshelf users: %w", err)
	}
	return users, nil
}

// matchABSUser picks the one active, OIDC-linked Audiobookshelf user whose
// username equals the member's, ignoring case as Audiobookshelf's own lookup
// does.
func matchABSUser(users []audiobookshelf.UserSummary, username string) (audiobookshelf.UserSummary, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return audiobookshelf.UserSummary{}, ErrABSUserNotFound
	}
	var found []audiobookshelf.UserSummary
	for _, user := range users {
		if !user.IsActive || !user.HasOpenIDLink {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(user.Username), username) {
			found = append(found, user)
		}
	}
	switch len(found) {
	case 0:
		return audiobookshelf.UserSummary{}, ErrABSUserNotFound
	case 1:
		return found[0], nil
	default:
		return audiobookshelf.UserSummary{}, ErrABSUserAmbiguous
	}
}

// GetABSLink reports a profile's current link.
func (s *MultiUserService) GetABSLink(profileID string) (*ABSLink, error) {
	profile, err := s.repository.GetProfileMetadata(profileID)
	if err != nil {
		return nil, err
	}
	if profile == nil {
		return nil, ErrProfileNotFound
	}
	return linkFromProfile(profile), nil
}

func linkFromProfile(profile *database.SyncProfile) *ABSLink {
	return &ABSLink{
		State:       database.NormalizeABSLinkState(profile.ABSLinkState),
		ABSUsername: profile.ABSUsername,
	}
}

// LinkABSUser matches the owner's username against Audiobookshelf and, on
// exactly one match, records it as pending. A pending or approved link is
// returned unchanged; matching runs again only from none or rejected.
func (s *MultiUserService) LinkABSUser(ctx context.Context, profileID, ownerUserID, ownerUsername string) (*ABSLink, error) {
	profile, err := s.repository.GetProfileMetadata(profileID)
	if err != nil {
		return nil, err
	}
	if profile == nil {
		return nil, ErrProfileNotFound
	}
	if profile.OwnerUserID == nil || *profile.OwnerUserID != ownerUserID {
		return nil, ErrABSLinkNotOwner
	}
	switch database.NormalizeABSLinkState(profile.ABSLinkState) {
	case database.ABSLinkStatePending, database.ABSLinkStateApproved:
		return linkFromProfile(profile), nil
	}

	users, err := s.listABSUsers(ctx)
	if err != nil {
		return nil, err
	}
	match, err := matchABSUser(users, ownerUsername)
	if err != nil {
		return nil, err
	}
	if err := s.repository.SetABSLink(profileID, match.ID, match.Username, database.ABSLinkStatePending,
		database.ABSLinkStateNone, database.ABSLinkStateRejected); err != nil {
		return nil, err
	}
	s.logger.Info("Audiobookshelf link pending approval", map[string]interface{}{
		"profile_id":   profileID,
		"abs_username": match.Username,
	})
	return &ABSLink{State: database.ABSLinkStatePending, ABSUsername: match.Username}, nil
}

// ApproveABSLink approves a pending link. Admin only; the caller checks.
func (s *MultiUserService) ApproveABSLink(profileID string) error {
	profile, err := s.repository.GetProfileMetadata(profileID)
	if err != nil {
		return err
	}
	if profile == nil {
		return ErrProfileNotFound
	}
	if profile.ABSUserID == nil {
		return database.ErrABSLinkStateConflict
	}
	return s.repository.SetABSLink(profileID, *profile.ABSUserID, profile.ABSUsername,
		database.ABSLinkStateApproved, database.ABSLinkStatePending)
}

// RejectABSLink rejects a pending link, or withdraws an approved one, and
// frees the Audiobookshelf user. Admin only; the caller checks.
func (s *MultiUserService) RejectABSLink(profileID string) error {
	profile, err := s.repository.GetProfileMetadata(profileID)
	if err != nil {
		return err
	}
	if profile == nil {
		return ErrProfileNotFound
	}
	return s.repository.ClearABSLink(profileID, database.ABSLinkStateRejected,
		database.ABSLinkStatePending, database.ABSLinkStateApproved)
}

// SetABSLinkManually links a profile to an Audiobookshelf user an admin chose.
// The admin picked it, so it is approved at once. Admin only; the caller
// checks.
func (s *MultiUserService) SetABSLinkManually(ctx context.Context, profileID, absUserID string) (*ABSLink, error) {
	profile, err := s.repository.GetProfileMetadata(profileID)
	if err != nil {
		return nil, err
	}
	if profile == nil {
		return nil, ErrProfileNotFound
	}
	users, err := s.listABSUsers(ctx)
	if err != nil {
		return nil, err
	}
	for _, user := range users {
		if user.ID != absUserID {
			continue
		}
		if !user.IsActive {
			return nil, ErrABSUserNotFound
		}
		if err := s.repository.SetABSLink(profileID, user.ID, user.Username, database.ABSLinkStateApproved); err != nil {
			return nil, err
		}
		s.logger.Info("Audiobookshelf link set by admin", map[string]interface{}{
			"profile_id":   profileID,
			"abs_username": user.Username,
		})
		return &ABSLink{State: database.ABSLinkStateApproved, ABSUsername: user.Username}, nil
	}
	return nil, ErrABSUserNotFound
}

// ListABSLinks returns every active profile's link for the admin view.
func (s *MultiUserService) ListABSLinks() ([]database.ABSLinkRow, error) {
	return s.repository.ListABSLinks()
}

// ListABSUserOptions returns the active Audiobookshelf users an admin can
// link a profile to.
func (s *MultiUserService) ListABSUserOptions(ctx context.Context) ([]ABSUserOption, error) {
	users, err := s.listABSUsers(ctx)
	if err != nil {
		return nil, err
	}
	options := make([]ABSUserOption, 0, len(users))
	for _, user := range users {
		if !user.IsActive {
			continue
		}
		options = append(options, ABSUserOption{ID: user.ID, Username: user.Username, HasOpenIDLink: user.HasOpenIDLink})
	}
	return options, nil
}

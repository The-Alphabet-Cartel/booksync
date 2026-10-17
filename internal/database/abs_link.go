package database

import (
	"errors"
	"fmt"

	"gorm.io/gorm"
)

// Booksync F2: repository operations for the member -> Audiobookshelf user
// link held on each sync profile.

// ErrABSUserAlreadyLinked means another active profile already holds the
// Audiobookshelf user. The unique index on abs_user_id is the backstop; this
// error is the readable form of the same refusal.
var ErrABSUserAlreadyLinked = errors.New("audiobookshelf user is already linked to another profile")

// ErrABSLinkStateConflict means the profile's link was not in the state the
// caller expected, for example approving a link that is not pending.
var ErrABSLinkStateConflict = errors.New("audiobookshelf link is not in the expected state")

// NormalizeABSLinkState maps the empty value an in-memory profile carries
// before it is reloaded to the database default.
func NormalizeABSLinkState(state string) string {
	if state == "" {
		return ABSLinkStateNone
	}
	return state
}

// ABSLinkRow is one profile's link as shown in the admin view.
type ABSLinkRow struct {
	ProfileID     string  `gorm:"column:profile_id" json:"profile_id"`
	ProfileName   string  `gorm:"column:profile_name" json:"profile_name"`
	OwnerUserID   *string `gorm:"column:owner_user_id" json:"owner_user_id,omitempty"`
	OwnerUsername string  `gorm:"column:owner_username" json:"owner_username"`
	ABSUserID     *string `gorm:"column:abs_user_id" json:"abs_user_id,omitempty"`
	ABSUsername   string  `gorm:"column:abs_username" json:"abs_username"`
	ABSLinkState  string  `gorm:"column:abs_link_state" json:"abs_link_state"`
}

// SetABSLink records an Audiobookshelf user on an active profile in the given
// state. When fromStates is non-empty the profile's current state must be one
// of them. It refuses with ErrABSUserAlreadyLinked when another active profile
// already holds the same Audiobookshelf user.
func (r *Repository) SetABSLink(profileID, absUserID, absUsername, state string, fromStates ...string) error {
	if absUserID == "" {
		return fmt.Errorf("audiobookshelf user id is required")
	}
	return r.db.GetDB().Transaction(func(tx *gorm.DB) error {
		profile, err := loadActiveProfileForLink(tx, profileID)
		if err != nil {
			return err
		}
		if !stateAllowed(profile.ABSLinkState, fromStates) {
			return ErrABSLinkStateConflict
		}

		var holders int64
		if err := tx.Model(&SyncProfile{}).
			Where("abs_user_id = ? AND id <> ?", absUserID, profileID).
			Count(&holders).Error; err != nil {
			return fmt.Errorf("failed to check audiobookshelf link: %w", err)
		}
		if holders > 0 {
			return ErrABSUserAlreadyLinked
		}

		if err := tx.Model(&SyncProfile{}).Where("id = ?", profileID).Updates(map[string]interface{}{
			"abs_user_id":    absUserID,
			"abs_username":   absUsername,
			"abs_link_state": state,
		}).Error; err != nil {
			return fmt.Errorf("failed to set audiobookshelf link: %w", err)
		}
		return nil
	})
}

// ClearABSLink removes the Audiobookshelf user from an active profile and sets
// its link state. When fromStates is non-empty the current state must be one
// of them.
func (r *Repository) ClearABSLink(profileID, state string, fromStates ...string) error {
	return r.db.GetDB().Transaction(func(tx *gorm.DB) error {
		profile, err := loadActiveProfileForLink(tx, profileID)
		if err != nil {
			return err
		}
		if !stateAllowed(profile.ABSLinkState, fromStates) {
			return ErrABSLinkStateConflict
		}
		if err := tx.Model(&SyncProfile{}).Where("id = ?", profileID).Updates(map[string]interface{}{
			"abs_user_id":    nil,
			"abs_username":   "",
			"abs_link_state": state,
		}).Error; err != nil {
			return fmt.Errorf("failed to clear audiobookshelf link: %w", err)
		}
		return nil
	})
}

// ListABSLinks returns every active profile's link with its owner's username,
// oldest profile first.
func (r *Repository) ListABSLinks() ([]ABSLinkRow, error) {
	var rows []ABSLinkRow
	err := r.db.GetDB().Table("sync_profiles").
		Select("sync_profiles.id AS profile_id, sync_profiles.name AS profile_name, "+
			"sync_profiles.owner_user_id AS owner_user_id, COALESCE(auth_users.username, '') AS owner_username, "+
			"sync_profiles.abs_user_id AS abs_user_id, COALESCE(sync_profiles.abs_username, '') AS abs_username, "+
			"COALESCE(sync_profiles.abs_link_state, '') AS abs_link_state").
		Joins("LEFT JOIN auth_users ON auth_users.id = sync_profiles.owner_user_id").
		Where("sync_profiles.active = ?", true).
		Order("sync_profiles.created_at ASC").
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("failed to list audiobookshelf links: %w", err)
	}
	for i := range rows {
		rows[i].ABSLinkState = NormalizeABSLinkState(rows[i].ABSLinkState)
	}
	return rows, nil
}

func loadActiveProfileForLink(tx *gorm.DB, profileID string) (*SyncProfile, error) {
	var profile SyncProfile
	if err := tx.Where("id = ? AND active = ?", profileID, true).First(&profile).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("sync profile not found: %s", profileID)
		}
		return nil, fmt.Errorf("failed to load sync profile: %w", err)
	}
	return &profile, nil
}

func stateAllowed(current string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	current = NormalizeABSLinkState(current)
	for _, state := range allowed {
		if current == state {
			return true
		}
	}
	return false
}

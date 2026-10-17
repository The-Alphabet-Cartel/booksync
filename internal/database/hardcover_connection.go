package database

import (
	"fmt"

	"gorm.io/gorm"
)

// Booksync F3: storage for a member's Hardcover OAuth connection. The token
// set is encrypted into sync_profile_configs.hardcover_token_encrypted, the
// column upstream used for a pasted personal token.

// NormalizeHardcoverState maps an unset state to the database default.
func NormalizeHardcoverState(state string) string {
	if state == "" {
		return HardcoverStateNone
	}
	return state
}

// SetHardcoverConnection stores an encrypted token set and marks the profile
// connected.
func (r *Repository) SetHardcoverConnection(profileID, tokenJSON, username string) error {
	encrypted, err := r.encryptor.Encrypt(tokenJSON)
	if err != nil {
		return fmt.Errorf("failed to encrypt Hardcover token: %w", err)
	}
	return r.db.GetDB().Transaction(func(tx *gorm.DB) error {
		if _, err := loadActiveProfileForLink(tx, profileID); err != nil {
			return err
		}
		if err := tx.Model(&SyncProfileConfig{}).Where("profile_id = ?", profileID).
			Update("hardcover_token_encrypted", encrypted).Error; err != nil {
			return fmt.Errorf("failed to store Hardcover token: %w", err)
		}
		return tx.Model(&SyncProfile{}).Where("id = ?", profileID).Updates(map[string]interface{}{
			"hardcover_state":    HardcoverStateConnected,
			"hardcover_username": username,
		}).Error
	})
}

// UpdateHardcoverToken replaces the stored token set after a refresh.
func (r *Repository) UpdateHardcoverToken(profileID, tokenJSON string) error {
	encrypted, err := r.encryptor.Encrypt(tokenJSON)
	if err != nil {
		return fmt.Errorf("failed to encrypt Hardcover token: %w", err)
	}
	return r.db.GetDB().Model(&SyncProfileConfig{}).Where("profile_id = ?", profileID).
		Update("hardcover_token_encrypted", encrypted).Error
}

// SetHardcoverState changes only the connection state, e.g. to
// needs_reconnect after Hardcover refused a refresh. The stored tokens stay
// until the member reconnects or disconnects.
func (r *Repository) SetHardcoverState(profileID, state string) error {
	return r.db.GetDB().Model(&SyncProfile{}).Where("id = ?", profileID).
		Update("hardcover_state", state).Error
}

// ClearHardcoverConnection deletes the stored tokens and marks the profile
// not connected.
func (r *Repository) ClearHardcoverConnection(profileID string) error {
	return r.db.GetDB().Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&SyncProfileConfig{}).Where("profile_id = ?", profileID).
			Update("hardcover_token_encrypted", "").Error; err != nil {
			return fmt.Errorf("failed to delete Hardcover token: %w", err)
		}
		return tx.Model(&SyncProfile{}).Where("id = ?", profileID).Updates(map[string]interface{}{
			"hardcover_state":    HardcoverStateNone,
			"hardcover_username": "",
		}).Error
	})
}

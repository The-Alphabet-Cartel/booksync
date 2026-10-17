package api

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/auth"
	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/database"
	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/hardcoveroauth"
	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/multiuser"
)

// Booksync F3: HTTP handlers for connecting a member's Hardcover account.

func hardcoverResponse(profile *database.SyncProfile) map[string]interface{} {
	if profile == nil {
		return map[string]interface{}{"state": database.HardcoverStateNone}
	}
	response := map[string]interface{}{
		"state": database.NormalizeHardcoverState(profile.HardcoverState),
	}
	if profile.HardcoverUsername != "" {
		response["username"] = profile.HardcoverUsername
	}
	return response
}

// hardcoverResultURL sends the browser back to the dashboard with an outcome
// the dashboard turns into a message. Only fixed codes, never error text.
func hardcoverResultURL(result string) string {
	return "/?hardcover=" + url.QueryEscape(result)
}

func hardcoverErrorCode(err error) string {
	switch {
	case errors.Is(err, hardcoveroauth.ErrNotConfigured):
		return "not_configured"
	case errors.Is(err, hardcoveroauth.ErrDenied):
		return "denied"
	case errors.Is(err, hardcoveroauth.ErrStateExpired):
		return "expired"
	case errors.Is(err, hardcoveroauth.ErrStateUnknown), errors.Is(err, hardcoveroauth.ErrStateUser):
		return "state"
	case errors.Is(err, hardcoveroauth.ErrIssuer):
		return "issuer"
	case errors.Is(err, multiuser.ErrHardcoverNotOwner):
		return "not_owner"
	case errors.Is(err, multiuser.ErrProfileNotFound):
		return "not_found"
	default:
		return "failed"
	}
}

// ConnectHardcover handles GET /api/profiles/{id}/hardcover/connect: the
// owner's browser is redirected to Hardcover's consent page.
func (h *Handler) ConnectHardcover(w http.ResponseWriter, r *http.Request) {
	profileID := profileIDFromRequest(r)
	if !h.authEnabled {
		h.writeErrorResponse(w, http.StatusNotFound, "Not found")
		return
	}
	if !h.authorizeProfile(w, r, profileID, true) {
		return
	}
	user, _ := auth.GetUserFromRequest(r)
	authURL, err := h.multiUserService.BeginHardcoverConnect(profileID, user.ID)
	if err != nil {
		h.log.Warn("Hardcover connect not started", map[string]interface{}{
			"profile_id": profileID,
			"error":      err.Error(),
		})
		http.Redirect(w, r, hardcoverResultURL("error:"+hardcoverErrorCode(err)), http.StatusFound)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// HardcoverCallback handles GET /auth/hardcover/callback, where Hardcover
// returns the member's browser.
func (h *Handler) HardcoverCallback(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.GetUserFromRequest(r)
	if !ok || user == nil {
		h.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	profileID, _, err := h.multiUserService.CompleteHardcoverConnect(r.Context(), user.ID, r.URL.Query())
	if err != nil {
		h.log.Warn("Hardcover connect failed", map[string]interface{}{
			"user_id": user.ID,
			"error":   err.Error(),
		})
		http.Redirect(w, r, hardcoverResultURL("error:"+hardcoverErrorCode(err)), http.StatusFound)
		return
	}
	h.log.Debug("Hardcover connect completed", map[string]interface{}{"profile_id": profileID})
	http.Redirect(w, r, hardcoverResultURL("connected"), http.StatusFound)
}

// DisconnectHardcover handles POST /api/profiles/{id}/hardcover/disconnect.
func (h *Handler) DisconnectHardcover(w http.ResponseWriter, r *http.Request) {
	profileID := profileIDFromRequest(r)
	if !h.authEnabled {
		h.writeErrorResponse(w, http.StatusNotFound, "Not found")
		return
	}
	if !h.authorizeProfile(w, r, profileID, true) {
		return
	}
	revokeErr, err := h.multiUserService.DisconnectHardcover(r.Context(), profileID)
	if err != nil {
		h.log.Error("Failed to disconnect Hardcover: " + err.Error())
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to disconnect Hardcover")
		return
	}
	h.writeSuccessResponse(w, map[string]interface{}{
		"state":   database.HardcoverStateNone,
		"revoked": revokeErr == nil,
	})
}

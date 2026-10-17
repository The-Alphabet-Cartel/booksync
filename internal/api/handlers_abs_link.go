package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/auth"
	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/database"
	"github.com/drallgood/audiobookshelf-hardcover-sync/internal/multiuser"
)

// Booksync F2: HTTP handlers for the member -> Audiobookshelf user link and
// the admin approval view.

// SetABSLinkRequest is the body of PUT /api/admin/profiles/{id}/abs-link.
type SetABSLinkRequest struct {
	ABSUserID string `json:"abs_user_id"`
}

func absLinkResponse(profile *database.SyncProfile) map[string]interface{} {
	if profile == nil {
		return map[string]interface{}{"state": database.ABSLinkStateNone}
	}
	response := map[string]interface{}{
		"state": database.NormalizeABSLinkState(profile.ABSLinkState),
	}
	if profile.ABSUsername != "" {
		response["abs_username"] = profile.ABSUsername
	}
	return response
}

// absLinkErrorMessage is what the member is told. It never carries anything
// from Audiobookshelf's response.
func absLinkErrorMessage(err error) string {
	switch {
	case errors.Is(err, multiuser.ErrABSUserNotFound):
		return "No Audiobookshelf account matches your username. Ask PB to link it by hand."
	case errors.Is(err, multiuser.ErrABSUserAmbiguous):
		return "More than one Audiobookshelf account matches your username. Ask PB to link it by hand."
	case errors.Is(err, database.ErrABSUserAlreadyLinked):
		return "That Audiobookshelf account is already linked to another profile. Ask PB."
	case errors.Is(err, multiuser.ErrABSNotConfigured):
		return "Audiobookshelf access is not set up on this server yet. Ask PB."
	default:
		return "Could not reach Audiobookshelf to link your account. Try again later."
	}
}

func absLinkErrorStatus(err error) int {
	switch {
	case errors.Is(err, multiuser.ErrProfileNotFound):
		return http.StatusNotFound
	case errors.Is(err, multiuser.ErrABSLinkNotOwner):
		return http.StatusForbidden
	case errors.Is(err, multiuser.ErrABSUserNotFound),
		errors.Is(err, multiuser.ErrABSUserAmbiguous):
		return http.StatusUnprocessableEntity
	case errors.Is(err, database.ErrABSUserAlreadyLinked),
		errors.Is(err, database.ErrABSLinkStateConflict):
		return http.StatusConflict
	case errors.Is(err, multiuser.ErrABSNotConfigured):
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadGateway
	}
}

func (h *Handler) logABSLinkFailure(profileID string, err error) {
	h.log.Warn("Audiobookshelf link not made", map[string]interface{}{
		"profile_id": profileID,
		"error":      err.Error(),
	})
}

// requireAdmin answers 404 to anyone who is not an admin, so the admin routes
// do not announce themselves. With authentication disabled there is no admin.
func (h *Handler) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !h.authEnabled {
		h.writeErrorResponse(w, http.StatusNotFound, "Not found")
		return false
	}
	user, authenticated := auth.GetUserFromRequest(r)
	if !authenticated || user == nil {
		h.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required")
		return false
	}
	if auth.UserRole(user.Role) != auth.RoleAdmin {
		h.writeErrorResponse(w, http.StatusNotFound, "Not found")
		return false
	}
	return true
}

// LinkProfileABS handles POST /api/profiles/{id}/abs-link: the owner asks for
// their profile to be matched to their Audiobookshelf user.
func (h *Handler) LinkProfileABS(w http.ResponseWriter, r *http.Request) {
	profileID := profileIDFromRequest(r)
	if profileID == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Profile ID is required")
		return
	}
	if !h.authEnabled {
		h.writeErrorResponse(w, http.StatusNotFound, "Not found")
		return
	}
	if !h.authorizeProfile(w, r, profileID, true) {
		return
	}
	user, _ := auth.GetUserFromRequest(r)
	link, err := h.multiUserService.LinkABSUser(r.Context(), profileID, user.ID, user.Username)
	if err != nil {
		h.logABSLinkFailure(profileID, err)
		if errors.Is(err, multiuser.ErrProfileNotFound) {
			h.writeErrorResponse(w, http.StatusNotFound, "Sync profile not found")
			return
		}
		if errors.Is(err, multiuser.ErrABSLinkNotOwner) {
			h.writeErrorResponse(w, http.StatusForbidden, "Only the profile's owner can link it")
			return
		}
		h.writeErrorResponse(w, absLinkErrorStatus(err), absLinkErrorMessage(err))
		return
	}
	h.writeSuccessResponse(w, link)
}

// ListABSLinks handles GET /api/admin/abs-links.
func (h *Handler) ListABSLinks(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	rows, err := h.multiUserService.ListABSLinks()
	if err != nil {
		h.log.Error("Failed to list audiobookshelf links: " + err.Error())
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list Audiobookshelf links")
		return
	}
	h.writeSuccessResponse(w, rows)
}

// ListABSUsers handles GET /api/admin/abs-users: id and username only, for a
// manual re-link.
func (h *Handler) ListABSUsers(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	options, err := h.multiUserService.ListABSUserOptions(r.Context())
	if err != nil {
		h.log.Error("Failed to list audiobookshelf users: " + err.Error())
		h.writeErrorResponse(w, absLinkErrorStatus(err), "Failed to list Audiobookshelf users")
		return
	}
	h.writeSuccessResponse(w, options)
}

// ApproveABSLink handles POST /api/admin/profiles/{id}/abs-link/approve.
func (h *Handler) ApproveABSLink(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	profileID := profileIDFromRequest(r)
	if err := h.multiUserService.ApproveABSLink(profileID); err != nil {
		h.writeErrorResponse(w, absLinkErrorStatus(err), "Cannot approve this link: "+adminLinkReason(err))
		return
	}
	h.writeAdminLink(w, profileID)
}

// RejectABSLink handles POST /api/admin/profiles/{id}/abs-link/reject.
func (h *Handler) RejectABSLink(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	profileID := profileIDFromRequest(r)
	if err := h.multiUserService.RejectABSLink(profileID); err != nil {
		h.writeErrorResponse(w, absLinkErrorStatus(err), "Cannot reject this link: "+adminLinkReason(err))
		return
	}
	h.writeAdminLink(w, profileID)
}

// SetABSLink handles PUT /api/admin/profiles/{id}/abs-link: an admin links a
// profile to a chosen Audiobookshelf user, approved at once.
func (h *Handler) SetABSLink(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	profileID := profileIDFromRequest(r)
	var req SetABSLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ABSUserID == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "abs_user_id is required")
		return
	}
	link, err := h.multiUserService.SetABSLinkManually(r.Context(), profileID, req.ABSUserID)
	if err != nil {
		h.writeErrorResponse(w, absLinkErrorStatus(err), "Cannot link this profile: "+adminLinkReason(err))
		return
	}
	h.writeSuccessResponse(w, link)
}

func (h *Handler) writeAdminLink(w http.ResponseWriter, profileID string) {
	link, err := h.multiUserService.GetABSLink(profileID)
	if err != nil {
		h.writeErrorResponse(w, absLinkErrorStatus(err), "Failed to read the link")
		return
	}
	h.writeSuccessResponse(w, link)
}

func adminLinkReason(err error) string {
	switch {
	case errors.Is(err, multiuser.ErrProfileNotFound):
		return "profile not found"
	case errors.Is(err, database.ErrABSLinkStateConflict):
		return "the link is not in a state that allows this"
	case errors.Is(err, database.ErrABSUserAlreadyLinked):
		return "that Audiobookshelf user is already linked to another profile"
	case errors.Is(err, multiuser.ErrABSUserNotFound):
		return "no active Audiobookshelf user with that id"
	case errors.Is(err, multiuser.ErrABSNotConfigured):
		return "Audiobookshelf admin access is not configured"
	default:
		return "unexpected error"
	}
}

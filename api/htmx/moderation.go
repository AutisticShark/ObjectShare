package htmx

import (
	"context"
	"fmt"
	"net/http"

	"github.com/AutisticShark/ObjectShare/db"
)

func (handler *Handler) AdminModerateUser(writer http.ResponseWriter, request *http.Request) {
	actor := currentIdentity(request)
	if actor == nil || !actor.User.IsAvailableAdmin() {
		http.Error(writer, "Forbidden", http.StatusForbidden)
		return
	}
	handler.adminUserAction(writer, request, func(ctx context.Context, id string) error {
		values := request.PostForm["moderation_status"]
		if len(values) != 1 || !db.ValidModerationStatus(values[0]) {
			return fmt.Errorf("%w: Choose a valid moderation status.", errInvalidAdminForm)
		}
		if id == actor.User.ID && values[0] != db.ModerationNone {
			return fmt.Errorf("%w: You cannot ban or shadowban your own account.", errInvalidAdminForm)
		}
		return handler.users.AdminModerateUser(ctx, id, values[0])
	}, "updated")
}

// Read current owner state at the access boundary, including for anonymous
// readers and old links. Lookup failures must never expose moderated files.
func (handler *Handler) fileModeration(request *http.Request, file *db.FileList) string {
	if file.FileOwner == nil {
		return db.ModerationNone
	}
	if handler.users == nil {
		return "unavailable"
	}
	owner, err := handler.users.UserByID(request.Context(), *file.FileOwner)
	if err != nil || owner == nil {
		return "unavailable"
	}
	return owner.ModerationStatus
}

func signedInFileOwner(request *http.Request, file *db.FileList) bool {
	user := identityUser(request)
	return user.CanAuthenticate() && file.FileOwner != nil && *file.FileOwner == user.ID
}

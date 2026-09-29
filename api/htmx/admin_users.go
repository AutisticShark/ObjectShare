package htmx

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type adminUserRow struct {
	ModerationStatus                                                                                string
	EmailVerified                                                                                   bool
	ID, Email, DisplayName, Role, CreatedAt, LastLogin, StorageUsed, CreditBalance, CreditRequestID string
	Active, IsCurrent, IsPaid                                                                       bool
	UploadQuotaMiB                                                                                  int64
}

type adminPageData struct {
	Version, CSRF, Error, Message, TotalStorageUsed   string
	Search, Filter, PreviousURL, NextURL, QuerySuffix string
	Page                                              int
	TotalUsers                                        int64
	User                                              *db.User
	Users                                             []adminUserRow
}

var errInvalidAdminForm = errors.New("invalid administrator form")

func (handler *Handler) AdminUsers(writer http.ResponseWriter, request *http.Request) {
	identity := currentIdentity(request)
	query, ok := adminDirectoryQuery(writer, request)
	if !ok {
		return
	}
	data, err := handler.adminUsersPageData(request.Context(), identity, query)
	if err != nil {
		handler.internalError(writer, request, "load user management data", err)
		return
	}
	data.Message = adminMessage(request.URL.Query().Get("message"))
	handler.render(writer, "admin_users.html", data)
}

func (handler *Handler) AdminCreateUser(writer http.ResponseWriter, request *http.Request) {
	identity := currentIdentity(request)
	if !handler.parseAuthForm(writer, request) || !handler.verifyJWTCSRF(writer, request, identity) {
		return
	}
	query, ok := adminDirectoryQuery(writer, request)
	if !ok {
		return
	}
	email, displayName, password, err := validatedRegistration(request)
	uploadQuotaBytes, quotaErr := uploadQuotaFromForm(request.FormValue("upload_quota_mib"))
	if err == nil {
		err = quotaErr
	}
	role := request.FormValue("role")
	if role != db.RoleAdmin && role != db.RoleUser {
		err = errors.New("Choose a valid role.")
	}
	if err != nil {
		handler.renderAdminError(writer, request, identity, err.Error())
		return
	}
	hash, err := appauth.HashPassword(password)
	if err != nil {
		handler.internalError(writer, request, "hash administrator-created password", err)
		return
	}
	err = handler.users.CreateUser(request.Context(), &db.User{ID: uuid.NewString(), Email: email, DisplayName: displayName, PasswordHash: hash, Role: role, Active: true, TokenVersion: 1, IsPaid: checked(request, "is_paid"), UploadQuotaBytes: uploadQuotaBytes})
	if errors.Is(err, db.ErrConflict) {
		handler.renderAdminError(writer, request, identity, "That email address is already registered.")
		return
	}
	if err != nil {
		handler.internalError(writer, request, "create administrator-managed user", err)
		return
	}
	if request.Header.Get("HX-Request") == "true" {
		data, err := handler.adminUsersPageData(request.Context(), identity, query)
		if err != nil {
			handler.internalError(writer, request, "reload user directory", err)
			return
		}
		data.Message = adminMessage("created")
		handler.render(writer, "admin_users.html", data)
		return
	}
	handler.redirect(writer, request, "/admin/users?message=created")
}

func (handler *Handler) AdminUpdateAccess(writer http.ResponseWriter, request *http.Request) {
	handler.adminUserAction(writer, request, func(ctx context.Context, id string) error {
		role := request.FormValue("role")
		if role != db.RoleAdmin && role != db.RoleUser {
			return fmt.Errorf("%w: Choose a valid role.", errInvalidAdminForm)
		}
		return handler.users.AdminUpdateUser(ctx, id, role, request.FormValue("active") == "true")
	}, "updated")
}

func (handler *Handler) AdminUpdateUploadQuota(writer http.ResponseWriter, request *http.Request) {
	handler.adminUserAction(writer, request, func(ctx context.Context, id string) error {
		quotaBytes, err := uploadQuotaFromForm(request.FormValue("upload_quota_mib"))
		if err != nil {
			return fmt.Errorf("%w: %v", errInvalidAdminForm, err)
		}
		return handler.users.UpdateUploadQuota(ctx, id, quotaBytes)
	}, "quota")
}

func (handler *Handler) AdminUpdatePaidStatus(writer http.ResponseWriter, request *http.Request) {
	handler.adminUserAction(writer, request, func(ctx context.Context, id string) error {
		paid := request.FormValue("is_paid")
		if paid != "true" && paid != "false" {
			return fmt.Errorf("%w: Choose a valid payment status.", errInvalidAdminForm)
		}
		return handler.users.UpdatePaidStatus(ctx, id, paid == "true")
	}, "paid")
}

func (handler *Handler) AdminAdjustCredit(writer http.ResponseWriter, request *http.Request) {
	if handler.billing == nil {
		http.Error(writer, "Billing storage is unavailable.", http.StatusServiceUnavailable)
		return
	}
	identity := currentIdentity(request)
	handler.adminUserAction(writer, request, func(ctx context.Context, id string) error {
		delta, err := strconv.ParseInt(strings.TrimSpace(request.FormValue("credit_delta")), 10, 64)
		description := strings.TrimSpace(request.FormValue("credit_description"))
		if err != nil || delta == 0 || delta < -1_000_000_000 || delta > 1_000_000_000 || description == "" || len(description) > 200 {
			return fmt.Errorf("%w: Enter a non-zero adjustment from -1000000000 to 1000000000 credits and a reason of at most 200 characters.", errInvalidAdminForm)
		}
		requestID := request.FormValue("credit_request_id")
		if _, err := uuid.Parse(requestID); err != nil {
			return fmt.Errorf("%w: Reload the users page before recording an adjustment.", errInvalidAdminForm)
		}
		_, err = handler.billing.AdjustCredit(ctx, id, delta, description, identity.User.ID, requestID, time.Now().UTC())
		if errors.Is(err, db.ErrConflict) {
			return fmt.Errorf("%w: This form was already used for another adjustment. Reload the users page.", errInvalidAdminForm)
		}
		if errors.Is(err, db.ErrInvalidCredit) {
			return fmt.Errorf("%w: The adjustment would exceed the supported account-credit range.", errInvalidAdminForm)
		}
		return err
	}, "credit")
}

func (handler *Handler) AdminResetPassword(writer http.ResponseWriter, request *http.Request) {
	handler.adminUserAction(writer, request, func(ctx context.Context, id string) error {
		password := request.FormValue("password")
		if password != request.FormValue("password_confirm") {
			return fmt.Errorf("%w: Passwords do not match.", errInvalidAdminForm)
		}
		if err := appauth.ValidatePassword(password); err != nil {
			return fmt.Errorf("%w: %v", errInvalidAdminForm, err)
		}
		hash, err := appauth.HashPassword(password)
		if err != nil {
			return err
		}
		_, err = handler.users.UpdatePassword(ctx, id, hash)
		return err
	}, "password")
}

func (handler *Handler) AdminDeleteUser(writer http.ResponseWriter, request *http.Request) {
	handler.adminUserAction(writer, request, func(ctx context.Context, id string) error {
		return handler.users.DeleteUser(ctx, id)
	}, "deleted")
}

func (handler *Handler) adminUserAction(writer http.ResponseWriter, request *http.Request, action func(context.Context, string) error, message string) {
	identity := currentIdentity(request)
	if !handler.parseAuthForm(writer, request) || !handler.verifyJWTCSRF(writer, request, identity) {
		return
	}
	query, ok := adminDirectoryQuery(writer, request)
	if !ok {
		return
	}
	id := chi.URLParam(request, "id")
	if parsed, err := uuid.Parse(id); err != nil || parsed.String() != strings.ToLower(id) {
		http.NotFound(writer, request)
		return
	}
	if err := action(request.Context(), id); err != nil {
		if errors.Is(err, db.ErrLastAdmin) {
			handler.renderAdminError(writer, request, identity, "The final active administrator cannot be disabled, demoted, banned, shadowbanned, or deleted.")
			return
		}
		if errors.Is(err, db.ErrNotFound) {
			http.NotFound(writer, request)
			return
		}
		if errors.Is(err, db.ErrModeratedUser) {
			handler.renderAdminError(writer, request, identity, "Remove the ban or shadowban before deleting this account; deletion would otherwise make its uploads anonymous and available again.")
			return
		}
		if errors.Is(err, errInvalidAdminForm) {
			handler.renderAdminError(writer, request, identity, strings.TrimPrefix(err.Error(), errInvalidAdminForm.Error()+": "))
			return
		}
		handler.internalError(writer, request, "perform administrator user action", err)
		return
	}
	// Re-render the same bounded directory for enhanced forms. Changes to the
	// acting administrator still redirect through authentication before any new
	// administrator data is returned (their role/token may have changed).
	if request.Header.Get("HX-Request") == "true" && id != identity.User.ID {
		data, err := handler.adminUsersPageData(request.Context(), identity, query)
		if err != nil {
			handler.internalError(writer, request, "reload user directory", err)
			return
		}
		data.Message = adminMessage(message)
		handler.render(writer, "admin_users.html", data)
		return
	}
	handler.redirect(writer, request, "/admin/users?message="+message)
}

func (handler *Handler) renderAdminError(writer http.ResponseWriter, request *http.Request, identity *identity, message string) {
	query, ok := adminDirectoryQuery(writer, request)
	if !ok {
		return
	}
	data, err := handler.adminUsersPageData(request.Context(), identity, query)
	if err != nil {
		handler.internalError(writer, request, "render admin error", err)
		return
	}
	data.Error = message
	handler.render(writer, "admin_users.html", data)
}

func adminDirectoryQuery(writer http.ResponseWriter, request *http.Request) (workspacePageData, bool) {
	return workspaceQuery(writer, request, "admin", "disabled", "banned", "shadowbanned", "verified", "unverified")
}

func (handler *Handler) adminUsersPageData(ctx context.Context, identity *identity, query workspacePageData) (adminPageData, error) {
	directory, err := handler.users.AdminUserDirectory(ctx, query.Search, query.Filter, query.Page)
	if err != nil {
		return adminPageData{}, err
	}
	users := directory.Users
	querySuffix := ""
	if query.Search != "" || query.Filter != "" || query.Page != 0 {
		querySuffix = "?" + url.Values{"q": {query.Search}, "filter": {query.Filter}, "page": {strconv.Itoa(query.Page)}}.Encode()
	}
	query.pagination("/admin/users", len(users) > db.WorkspacePageSize)
	if len(users) > db.WorkspacePageSize {
		users = users[:db.WorkspacePageSize]
	}
	rows := make([]adminUserRow, 0, len(users))
	for _, user := range users {
		lastLogin := "Never"
		if user.LastLoginAt != nil {
			lastLogin = user.LastLoginAt.UTC().Format("2006-01-02 15:04 UTC")
		}
		storageUsed := directory.Usage[user.ID]
		rows = append(rows, adminUserRow{ID: user.ID, Email: user.Email, DisplayName: user.DisplayName, Role: user.Role,
			EmailVerified: user.EmailVerifiedAt != nil, ModerationStatus: user.ModerationStatus,
			Active: user.Active, CreatedAt: user.CreatedAt.UTC().Format("2006-01-02"), LastLogin: lastLogin,
			IsCurrent: user.ID == identity.User.ID, IsPaid: user.IsPaid, UploadQuotaMiB: user.UploadQuotaBytes / mebibyte,
			StorageUsed: humanSize(storageUsed), CreditBalance: fmt.Sprintf("%d credits", user.CreditBalance), CreditRequestID: uuid.NewString()})
	}
	return adminPageData{Version: config.GetVersion(), CSRF: identity.Claims.CSRF, User: identity.User, Users: rows,
		TotalStorageUsed: humanSize(directory.TotalStorageUsed), TotalUsers: directory.TotalUsers,
		Search: query.Search, Filter: query.Filter, Page: query.Page, PreviousURL: query.PreviousURL, NextURL: query.NextURL, QuerySuffix: querySuffix}, nil
}

const maxUploadQuotaMiB int64 = 8_796_093_022_207

func uploadQuotaFromForm(value string) (int64, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, nil
	}
	quotaMiB, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil || quotaMiB < 0 || quotaMiB > maxUploadQuotaMiB {
		return 0, fmt.Errorf("Upload quota must be a whole number from 0 to %d MiB.", maxUploadQuotaMiB)
	}
	return quotaMiB * mebibyte, nil
}

func adminMessage(value string) string {
	return map[string]string{"setup": "Initial administrator created.", "created": "User created.", "updated": "Access updated; that user's earlier JWTs were invalidated.", "quota": "Upload quota updated.", "paid": "Manual retention exemption updated.", "credit": "Account credit adjusted.", "password": "Password reset; that user's earlier JWTs were invalidated.", "deleted": "User deleted."}[value]
}

package htmx

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
)

type workspaceFile struct {
	accountFile
	Access    string
	Encrypted bool
}

type workspacePageData struct {
	Version, CSRF, Search, Filter, PreviousURL, NextURL, QuotaLabel string
	User                                                            *db.User
	Files                                                           []workspaceFile
	Invoices                                                        []db.Invoice
	Page                                                            int
}

type setupCheck struct {
	Name, Detail, URL string
	Configured        bool
}

type overviewPageData struct {
	Version, CSRF, Storage, StorageService string
	User                                   *db.User
	Stats                                  db.Overview
	Checks                                 []setupCheck
}

func (handler *Handler) workspaceRepo(writer http.ResponseWriter) db.WorkspaceRepository {
	repo, _ := handler.repository.(db.WorkspaceRepository)
	if repo == nil {
		http.Error(writer, "Workspace data is unavailable.", http.StatusServiceUnavailable)
	}
	return repo
}

func workspaceQuery(writer http.ResponseWriter, request *http.Request, filters ...string) (workspacePageData, bool) {
	data := workspacePageData{Version: config.GetVersion(), User: identityUser(request),
		Search: strings.TrimSpace(request.URL.Query().Get("q")), Filter: request.URL.Query().Get("filter")}
	if identity := currentIdentity(request); identity != nil && identity.Claims != nil {
		data.CSRF = identity.Claims.CSRF
	}
	if len(data.Search) > 255 || !utf8.ValidString(data.Search) || strings.ContainsRune(data.Search, 0) {
		http.Error(writer, "Search must be valid text of 255 bytes or fewer, without null characters.", http.StatusBadRequest)
		return data, false
	}
	validFilter := data.Filter == ""
	for _, filter := range filters {
		validFilter = validFilter || data.Filter == filter
	}
	page := request.URL.Query().Get("page")
	var err error
	if page != "" {
		data.Page, err = strconv.Atoi(page)
	}
	if !validFilter || err != nil || data.Page < 0 || data.Page > 100000 {
		http.Error(writer, "Invalid filter or page.", http.StatusBadRequest)
		return data, false
	}
	return data, true
}

func (data *workspacePageData) pagination(path string, hasNext bool) {
	link := func(page int) string {
		values := url.Values{"q": {data.Search}, "filter": {data.Filter}, "page": {strconv.Itoa(page)}}
		return path + "?" + values.Encode()
	}
	if data.Page > 0 {
		data.PreviousURL = link(data.Page - 1)
	}
	if hasNext && data.Page < 100000 {
		data.NextURL = link(data.Page + 1)
	}
	data.Page++ // Human-readable page number.
}

func (handler *Handler) Files(writer http.ResponseWriter, request *http.Request) {
	data, ok := workspaceQuery(writer, request, "link", "signed_in", "selected", "private")
	if !ok {
		return
	}
	repo := handler.workspaceRepo(writer)
	if repo == nil {
		return
	}
	files, err := repo.OwnerFiles(request.Context(), data.User.ID, data.Search, data.Filter, data.Page)
	if err != nil {
		handler.internalError(writer, request, "list workspace files", err)
		return
	}
	data.pagination("/files", len(files) > db.WorkspacePageSize)
	if len(files) > db.WorkspacePageSize {
		files = files[:db.WorkspacePageSize]
	}
	for _, file := range files {
		access := "Anyone with the link"
		switch file.ShareMode {
		case "signed_in":
			access = "Signed-in users"
		case "selected":
			access = "Selected accounts"
		case "private":
			access = "Only me"
		}
		data.Files = append(data.Files, workspaceFile{accountFile: accountFile{ID: file.FileID, Name: file.FileName,
			Size: humanSize(file.FileSize), CreatedAt: file.CreatedAt.UTC().Format("2006-01-02 15:04 UTC")}, Access: access, Encrypted: file.ClientEncryption != ""})
	}
	data.QuotaLabel = handler.uploadQuotaLabel(request, data.User)
	handler.render(writer, "files.html", data)
}

func (handler *Handler) AdminDashboard(writer http.ResponseWriter, request *http.Request) {
	repo := handler.workspaceRepo(writer)
	if repo == nil {
		return
	}
	stats, err := repo.AdminOverview(request.Context(), time.Now().UTC())
	if err != nil {
		handler.internalError(writer, request, "load administrator overview", err)
		return
	}
	cfg := handler.config
	checks := []setupCheck{
		{"HTTPS cookies", "Enable secure cookies when your public site uses HTTPS.", "/admin/settings#application-policy", cfg.SecureCookies},
		{"Outgoing email", "Send a test email from Configuration to verify delivery.", "/admin/settings#outgoing-email", cfg.Email != nil && cfg.Email.Provider != "" && cfg.Email.Provider != "none"},
		{"Email verification", "Set the public site URL and email provider for verification links.", "/admin/settings#application-policy", handler.verificationEnabled()},
		{"Payment gateways", "Enable Stripe or PayPal for online payments; account credit also works without a gateway.", "/admin/settings#billing-gateways", len(handler.billingGateways) > 0},
		{"Request rate limits", "Configure shared request limits and your trusted proxy addresses.", "/admin/settings", cfg.RateLimit != nil && cfg.RateLimit.Enabled},
		{"Direct uploads", "Use direct object-storage uploads for large files behind Cloudflare.", "/admin/settings", handler.direct != nil},
	}
	handler.render(writer, "admin_dashboard.html", overviewPageData{Version: config.GetVersion(), CSRF: identityCSRF(request), User: identityUser(request),
		Stats: stats, Storage: humanSize(stats.StorageBytes), StorageService: cfg.StorageService, Checks: checks})
}

func (handler *Handler) AdminInvoiceList(writer http.ResponseWriter, request *http.Request) {
	data, ok := workspaceQuery(writer, request, "pending", "paid", "unsent")
	if !ok {
		return
	}
	repo := handler.workspaceRepo(writer)
	if repo == nil {
		return
	}
	invoices, err := repo.AdminInvoices(request.Context(), data.Search, data.Filter, data.Page)
	if err != nil {
		handler.internalError(writer, request, "list administrator invoices", err)
		return
	}
	data.pagination("/admin/invoices", len(invoices) > db.WorkspacePageSize)
	if len(invoices) > db.WorkspacePageSize {
		invoices = invoices[:db.WorkspacePageSize]
	}
	data.Invoices = invoices
	handler.render(writer, "admin_invoices.html", data)
}

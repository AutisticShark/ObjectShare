package htmx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/google/uuid"
)

type workspaceStub struct {
	*authMemoryRepository
	owner, search, filter string
	page, calls           int
	err                   error
}

func (repo *workspaceStub) OwnerFiles(_ context.Context, owner, search, filter string, page int) ([]db.FileList, error) {
	repo.owner, repo.search, repo.filter, repo.page = owner, search, filter, page
	repo.calls++
	files := make([]db.FileList, 26)
	for i := range files {
		files[i] = db.FileList{FileID: uuid.NewString(), FileName: "<script>owner file</script>", ShareMode: "private"}
	}
	return files, repo.err
}
func (repo *workspaceStub) AdminOverview(context.Context, time.Time) (db.Overview, error) {
	repo.calls++
	return db.Overview{Users: 17}, repo.err
}
func (repo *workspaceStub) AdminInvoices(context.Context, string, string, int) ([]db.Invoice, error) {
	repo.calls++
	return []db.Invoice{{ID: uuid.NewString(), Email: "<script>customer</script>", Name: "Plan", Status: "paid"}}, repo.err
}

func TestWorkspaceAuthenticationAuthorizationAndEscaping(t *testing.T) {
	for _, role := range []string{"guest", "user", "admin", "banned", "shadowbanned", "disabled"} {
		for _, path := range []string{"/files", "/billing", "/admin", "/admin/invoices"} {
			t.Run(role+path, func(t *testing.T) {
				repo := &workspaceStub{authMemoryRepository: newAuthMemoryRepository()}
				h := newAuthTestHandler(t, repo.authMemoryRepository, false)
				h.repository = repo
				var err error
				h.templates, err = parseTemplates(os.DirFS("../.."), config.BrandingConfig{})
				if err != nil {
					t.Fatal(err)
				}
				u := &db.User{ID: uuid.NewString(), Role: db.RoleUser, Active: true, TokenVersion: 1}
				if role == "admin" {
					u.Role = db.RoleAdmin
				}
				if role == "banned" {
					u.ModerationStatus = db.ModerationBanned
				}
				if role == "shadowbanned" {
					u.ModerationStatus = db.ModerationShadowbanned
				}
				if role == "disabled" {
					u.Active = false
				}
				repo.users[u.ID] = u
				req := httptest.NewRequest("GET", path+"?q=report%26file&filter=private&page=1", nil)
				if path != "/files" {
					req = httptest.NewRequest("GET", path, nil)
				}
				if role != "guest" {
					token, _ := issueTestJWT(t, h, u)
					req.Header.Set("Authorization", "Bearer "+token)
				}
				fn := http.HandlerFunc(h.Files)
				if path == "/billing" {
					fn = h.BillingOverview
				}
				if path == "/admin" {
					fn = h.AdminDashboard
				}
				if path == "/admin/invoices" {
					fn = h.AdminInvoiceList
				}
				protected := h.RequireUser(fn)
				if strings.HasPrefix(path, "/admin") {
					protected = h.RequireAdmin(fn)
				}
				res := httptest.NewRecorder()
				h.Authenticate(protected).ServeHTTP(res, req)
				want := 200
				if role == "guest" || role == "disabled" {
					want = 303
				} else if role == "banned" || (strings.HasPrefix(path, "/admin") && role != "admin") {
					want = 403
				}
				if res.Code != want {
					t.Fatalf("status=%d want=%d body=%s", res.Code, want, res.Body.String())
				}
				if want != 200 {
					if repo.calls != 0 {
						t.Fatal("unauthorized request read workspace data")
					}
					return
				}
				body := res.Body.String()
				if !strings.HasSuffix(strings.TrimSpace(body), "</html>") || strings.Contains(body, "<script>owner") || strings.Contains(body, "<script>customer") {
					t.Fatal("incomplete or unsafe template output")
				}
				if res.Header().Get("Cache-Control") != "private, no-store" {
					t.Fatal("private page is cacheable")
				}
				if path == "/files" && (repo.owner != u.ID || repo.search != "report&file" || repo.filter != "private" || repo.page != 1 || !strings.Contains(body, "rel=\"next\"")) {
					t.Fatal("file scope or pagination not preserved")
				}
				if path == "/admin" && strings.Contains(body, `bg-green-lt">Configured`) {
					t.Fatal("disabled configuration reported as configured")
				}
			})
		}
	}
}

func TestWorkspaceRejectsUnboundedQueriesAndReportsRepositoryFailure(t *testing.T) {
	for _, query := range []string{"page=-1", "page=100001", "page=no", "filter=unknown", "q=%00", "q=%ff", "q=" + strings.Repeat("a", 256)} {
		response := httptest.NewRecorder()
		_, ok := workspaceQuery(response, httptest.NewRequest("GET", "/files?"+query, nil), "private")
		if ok || response.Code != 400 {
			t.Fatalf("accepted %s", query)
		}
	}
	repo := &workspaceStub{authMemoryRepository: newAuthMemoryRepository(), err: errors.New("database unavailable")}
	h := newAuthTestHandler(t, repo.authMemoryRepository, false)
	h.repository = repo
	response := httptest.NewRecorder()
	h.AdminDashboard(response, httptest.NewRequest("GET", "/admin", nil))
	if response.Code != 500 || strings.Contains(response.Body.String(), "database unavailable") {
		t.Fatal("failed dashboard exposed internals or presented success")
	}
}

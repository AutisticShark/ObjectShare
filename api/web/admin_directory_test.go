package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/AutisticShark/ObjectShare/db"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestAdminDirectoryPaginationFilteringAndActionContext(t *testing.T) {
	repo := newAuthMemoryRepository()
	admin := &db.User{ID: uuid.NewString(), Email: "admin@example.test", DisplayName: "Admin", Role: db.RoleAdmin, Active: true, TokenVersion: 1}
	repo.users[admin.ID] = admin
	var target *db.User
	for i := 0; i < 30; i++ {
		user := &db.User{ID: uuid.NewString(), Email: fmt.Sprintf("member%02d@example.test", i), DisplayName: "Member", Role: db.RoleUser, Active: true, TokenVersion: 1}
		if i == 29 {
			user.DisplayName = "needle_%"
			target = user
		}
		repo.users[user.ID] = user
	}
	h := newAuthTestHandler(t, repo, false)
	token, claims := issueTestJWT(t, h, admin)
	router := chi.NewRouter()
	router.Use(h.Authenticate)
	router.Group(func(r chi.Router) {
		r.Use(h.RequireAdmin)
		r.Get("/admin/users", h.AdminUsers)
		r.Post("/admin/users", h.AdminCreateUser)
		r.Post("/admin/users/{id}/quota", h.AdminUpdateUploadQuota)
	})
	get := func(path, cookie string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: "objectshare_jwt", Value: cookie})
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	// directory decodes an administrator directory response into its page data
	// and the account rows the page carries.
	directory := func(response *httptest.ResponseRecorder) (map[string]any, []any) {
		t.Helper()
		page, data := pageOf(t, response.Body.String())
		if page != "admin_users" {
			t.Fatalf("rendered page %q, want admin_users", page)
		}
		rows, _ := data["Users"].([]any)
		return data, rows
	}
	first := get("/admin/users", token)
	firstData, firstRows := directory(first)
	if first.Code != 200 || len(firstRows) != 25 || firstData["TotalUsers"] != float64(31) || firstData["NextURL"] == "" || firstData["PreviousURL"] != "" {
		t.Fatal("directory did not bound rows or expose navigation/global count")
	}
	second := get("/admin/users?page=1", token)
	secondData, secondRows := directory(second)
	if second.Code != 200 || len(secondRows) != 6 || secondData["PreviousURL"] == "" || secondData["NextURL"] != "" {
		t.Fatal("directory second page did not expose remaining accounts")
	}
	query := url.Values{"q": {"needle_%"}}.Encode()
	filtered := get("/admin/users?"+query, token)
	filteredData, filteredRows := directory(filtered)
	if filtered.Code != 200 || len(filteredRows) != 1 {
		t.Fatal("search did not isolate the account")
	}
	if filteredData["QuerySuffix"] != "?filter=&page=0&q=needle_%25" {
		t.Fatalf("actions lost encoded directory context: %v", filteredData["QuerySuffix"])
	}
	for _, quota := range []string{"invalid", "12"} {
		request := formRequest("/admin/users/"+target.ID+"/quota?"+query, url.Values{"csrf_token": {claims.CSRF}, "upload_quota_mib": {quota}})
		request.AddCookie(&http.Cookie{Name: "objectshare_jwt", Value: token})
		request.Header.Set(fetchRequestHeader, "true")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		data, rows := directory(response)
		if response.Code != 200 || response.Header().Get(fetchRedirectHeader) != "" || len(rows) != 1 || data["Search"] != "needle_%" {
			t.Fatalf("action lost its directory: quota=%s status=%d body=%s", quota, response.Code, response.Body.String())
		}
	}
	if target.UploadQuotaBytes != 12*mebibyte {
		t.Fatal("quota update did not persist")
	}
	create := formRequest("/admin/users?"+query, url.Values{
		"csrf_token": {claims.CSRF}, "display_name": {"needle_% new"}, "email": {"new@example.test"}, "role": {db.RoleUser},
		"password": {"a sufficiently long password"}, "password_confirm": {"a sufficiently long password"}, "upload_quota_mib": {"0"},
	})
	create.AddCookie(&http.Cookie{Name: "objectshare_jwt", Value: token})
	create.Header.Set(fetchRequestHeader, "true")
	created := httptest.NewRecorder()
	router.ServeHTTP(created, create)
	createdData, createdRows := directory(created)
	if created.Code != 200 || created.Header().Get(fetchRedirectHeader) != "" || len(createdRows) != 2 || createdData["TotalUsers"] != float64(32) {
		t.Fatal("account creation did not preserve directory context and update totals")
	}
	for _, query := range []string{"page=-1", "page=100001", "filter=unknown", "q=%00"} {
		if response := get("/admin/users?"+query, token); response.Code != 400 {
			t.Fatalf("invalid query accepted: %s", query)
		}
	}
	request := formRequest("/admin/users/"+target.ID+"/quota?filter=unknown", url.Values{"csrf_token": {claims.CSRF}, "upload_quota_mib": {"99"}})
	request.AddCookie(&http.Cookie{Name: "objectshare_jwt", Value: token})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != 400 || target.UploadQuotaBytes != 12*mebibyte {
		t.Fatal("invalid directory context mutated an account")
	}
	memberToken, _ := issueTestJWT(t, h, target)
	if response := get("/admin/users?q=needle", memberToken); response.Code != 403 || strings.Contains(response.Body.String(), "needle_%") {
		t.Fatal("directory bypassed administrator authorization")
	}
	if response := get("/admin/users", ""); response.Code != 303 {
		t.Fatal("guest directory request was not redirected to login")
	}
}

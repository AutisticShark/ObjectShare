package htmx

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/go-chi/chi/v5"
)

func TestBillingFailuresGiveBrowserRecoveryWithoutChangingAPIStatus(t *testing.T) {
	const owner = "11111111-1111-4111-8111-111111111111"
	const id = "22222222-2222-4222-8222-222222222222"
	repo := &invoiceTestRepository{entitlementRepository: &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}}, invoice: db.Invoice{ID: id, UserID: owner, Kind: "plan"}}
	handler := newTestHandler(t, repo, &memoryStorage{objects: make(map[string][]byte)})
	router := chi.NewRouter()
	router.Post("/invoices/{id}/pay", handler.PayInvoice)
	for _, failure := range []struct {
		err    error
		status int
	}{
		{db.ErrInsufficientCredit, 402}, {db.ErrConflict, 409}, {db.ErrInvalidCredit, 400}, {errors.New("provider-secret-do-not-expose"), 500}, {db.ErrNotFound, 404},
	} {
		for _, client := range []struct {
			accept, transport, htmx string
			html                    bool
		}{
			{"text/html,application/xhtml+xml", transportCookie, "", true},
			{"text/html;q=0.8", transportCookie, "", true},
			{"text/html", transportBearer, "", false},
			{"text/html;q=0", transportCookie, "", false},
			{"text/html;q=invalid", transportCookie, "", false},
			{"text/html", transportCookie, "true", false},
			{"", transportCookie, "", false},
		} {
			repo.purchaseErr = failure.err
			request := httptest.NewRequest("POST", "/invoices/"+id+"/pay", strings.NewReader("gateway=credit&csrf_token=expected"))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.Header.Set("Accept", client.accept)
			request.Header.Set("HX-Request", client.htmx)
			request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: &db.User{ID: owner, Role: db.RoleUser}, Transport: client.transport, Claims: &appauth.Claims{CSRF: "expected"}}))
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != failure.status {
				t.Fatalf("%v, %q: status %d", failure.err, client.accept, response.Code)
			}
			body := response.Body.String()
			if strings.Contains(body, "provider-secret") {
				t.Fatal("raw provider error leaked")
			}
			wantHTML := client.html && failure.status != 404
			if strings.HasPrefix(response.Header().Get("Content-Type"), "text/html") != wantHTML {
				t.Fatalf("wrong content type: %s", response.Header().Get("Content-Type"))
			}
			if wantHTML {
				page, data := pageOf(t, body)
				if page != "billing_problem" || data["InvoiceURL"] != "/invoices/"+id || data["Message"] == "" || !strings.HasSuffix(strings.TrimSpace(body), "</html>") {
					t.Fatalf("browser error does not provide a complete invoice recovery page: %s %v", page, data)
				}
			}
			if failure.status != 404 && response.Header().Get("Cache-Control") != "private, no-store" {
				t.Fatal("billing error is cacheable")
			}
		}
	}
}

func TestPaidInvoiceReceiptStateMatchesDeliveryConfiguration(t *testing.T) {
	const owner = "11111111-1111-4111-8111-111111111111"
	const id = "22222222-2222-4222-8222-222222222222"
	repo := &invoiceTestRepository{entitlementRepository: &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}}, invoice: db.Invoice{ID: id, UserID: owner, Kind: "plan", Status: "paid"}}
	handler := newTestHandler(t, repo, &memoryStorage{objects: make(map[string][]byte)})
	router := chi.NewRouter()
	router.Get("/invoices/{id}", handler.Invoice)
	for _, test := range []struct {
		provider string
		sent     bool
		enabled  bool
	}{
		{"none", false, false}, {"smtp", false, true}, {"smtp", true, true}, {"none", true, false},
	} {
		handler.config.Email = &config.EmailConfig{Provider: test.provider}
		repo.invoice.EmailSentAt = nil
		if test.sent {
			now := time.Now().UTC()
			repo.invoice.EmailSentAt = &now
		}
		request := httptest.NewRequest("GET", "/invoices/"+id, nil)
		request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: &db.User{ID: owner}, Claims: &appauth.Claims{CSRF: "expected"}}))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		page, data := pageOf(t, response.Body.String())
		if response.Code != 200 || page != "invoice" {
			t.Fatalf("%s sent=%v: %d %s", test.provider, test.sent, response.Code, response.Body.String())
		}
		// The page decides between "not enabled", "queued" and "accepted" from
		// these two values.
		invoice, _ := data["Invoice"].(map[string]any)
		if data["ReceiptEnabled"] != test.enabled || (invoice["EmailSentAt"] != nil) != test.sent {
			t.Fatalf("%s sent=%v: receipt enabled=%v, EmailSentAt=%v", test.provider, test.sent, data["ReceiptEnabled"], invoice["EmailSentAt"])
		}
	}
}

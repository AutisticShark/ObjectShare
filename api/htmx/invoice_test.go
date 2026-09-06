package htmx

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/AutisticShark/ObjectShare/email"
	"github.com/go-chi/chi/v5"
)

type invoiceTestRepository struct {
	*entitlementRepository
	db.InvoiceRepository
	invoice       db.Invoice
	created, paid bool
	legacy        *db.LegacyInvoicePayment
}

func (repo *invoiceTestRepository) ApplyLegacyInvoicePayment(_ context.Context, payment db.LegacyInvoicePayment, _ time.Time) error {
	repo.legacy = &payment
	return nil
}

func TestPaidLegacyReceiptsPassVerifiedAmountsToInvoices(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	repo := &invoiceTestRepository{entitlementRepository: &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}, plan: &db.PaidPlan{ID: "mapped-plan"}}}
	handler := newTestHandler(t, repo, &memoryStorage{objects: make(map[string][]byte)})
	handler.billingGateways = map[string]billingGateway{db.BillingGatewayStripe: newStripeClient(config.StripeBillingConfig{Enabled: true, WebhookSecret: "test-secret"})}
	payload := fmt.Sprintf(`{"id":"evt-paid","type":"invoice.paid","created":%d,"data":{"object":{"id":"in-paid","status":"paid","subscription":"sub-1","currency":"usd","amount_paid":1234,"status_transitions":{"paid_at":%d},"lines":{"data":[{"type":"subscription","price":{"id":"price-plus"},"period":{"start":%d,"end":%d}}]}}}}`, now.Unix(), now.Unix(), now.Unix(), now.AddDate(0, 0, 30).Unix())
	mac := hmac.New(sha256.New, []byte("test-secret"))
	fmt.Fprintf(mac, "%d.%s", now.Unix(), payload)
	request := httptest.NewRequest("POST", "/api/v1/billing/stripe/webhook", strings.NewReader(payload))
	request.Header.Set("Stripe-Signature", fmt.Sprintf("t=%d,v1=%s", now.Unix(), hex.EncodeToString(mac.Sum(nil))))
	response := httptest.NewRecorder()
	handler.StripeWebhook(response, request)
	if response.Code != 204 || repo.legacy == nil || repo.legacy.AmountMinor != 1234 || repo.legacy.PlanID != "mapped-plan" {
		t.Fatalf("Stripe invoice receipt: %d %#v %s", response.Code, repo.legacy, response.Body.String())
	}
	repo.legacy = nil
	response = httptest.NewRecorder()
	handler.StripeWebhook(response, httptest.NewRequest("POST", "/api/v1/billing/stripe/webhook", strings.NewReader(payload)))
	if response.Code != 400 || repo.legacy != nil {
		t.Fatal("unsigned invoice accepted")
	}
	gateway := &paypalGatewayStub{verified: true, details: paypalSubscription{ID: "I-1", PlanID: "P-1"}}
	gateway.details.BillingInfo.LastPayment.Time = now.Format(time.RFC3339)
	gateway.details.BillingInfo.NextBillingTime = now.AddDate(0, 0, 30).Format(time.RFC3339)
	handler.billingGateways = map[string]billingGateway{db.BillingGatewayPayPal: gateway}
	payload = fmt.Sprintf(`{"id":"WH-paid","event_type":"PAYMENT.SALE.COMPLETED","create_time":%q,"resource":{"id":"sale-1","state":"completed","billing_agreement_id":"I-1","create_time":%q,"amount":{"total":"12.34","currency":"USD"}}}`, now.Format(time.RFC3339), now.Format(time.RFC3339))
	response = httptest.NewRecorder()
	handler.PayPalWebhook(response, httptest.NewRequest("POST", "/api/v1/billing/paypal/webhook", strings.NewReader(payload)))
	if response.Code != 204 || repo.legacy == nil || repo.legacy.AmountMinor != 1234 || repo.legacy.PlanID != "mapped-plan" || !repo.legacy.PeriodEnd.Equal(now.AddDate(0, 0, 30)) {
		t.Fatalf("PayPal invoice receipt: %d %#v %s", response.Code, repo.legacy, response.Body.String())
	}
	repo.legacy = nil
	gateway.verified = false
	response = httptest.NewRecorder()
	handler.PayPalWebhook(response, httptest.NewRequest("POST", "/api/v1/billing/paypal/webhook", strings.NewReader(payload)))
	if response.Code != 400 || repo.legacy != nil {
		t.Fatal("unverified PayPal invoice accepted")
	}
}

type invoiceOutboxStub struct {
	*entitlementRepository
	db.InvoiceRepository
	invoice                      db.Invoice
	claimed, finished, delivered bool
	cancel                       context.CancelFunc
}

func (repo *invoiceOutboxStub) ClaimInvoiceEmail(context.Context, time.Time) (*db.Invoice, error) {
	if repo.claimed {
		return nil, db.ErrNotFound
	}
	repo.claimed = true
	return &repo.invoice, nil
}
func (repo *invoiceOutboxStub) FinishInvoiceEmail(_ context.Context, id, lease string, sent bool, _ time.Time) error {
	if id != repo.invoice.ID || lease != repo.invoice.EmailLease {
		return db.ErrConflict
	}
	repo.finished, repo.delivered = true, sent
	repo.cancel()
	return nil
}

type invoiceSenderFunc func(context.Context, email.Message) error

func (send invoiceSenderFunc) Send(ctx context.Context, message email.Message) error {
	return send(ctx, message)
}

func TestInvoiceEmailWorkerSendsPDFAndRetainsFailures(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "accepted", true: "retry"}[fail], func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			now := time.Now().UTC()
			repo := &invoiceOutboxStub{entitlementRepository: &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}}, cancel: cancel,
				invoice: db.Invoice{ID: "invoice-id", Name: "Plus", Status: "paid", Email: "buyer@example.com", AmountMinor: 1000, Currency: "USD", PaidAt: &now, CreatedAt: now, EmailLease: "lease-token"}}
			handler := newTestHandler(t, repo, &memoryStorage{objects: make(map[string][]byte)})
			handler.config.Email = &config.EmailConfig{Provider: "smtp"}
			calls := 0
			handler.emailSender = invoiceSenderFunc(func(_ context.Context, m email.Message) error {
				calls++
				if m.To != repo.invoice.Email || !strings.Contains(m.Subject, "Payment confirmed") || len(m.Attachments) != 1 || m.Attachments[0].ContentType != "application/pdf" || !strings.HasPrefix(string(m.Attachments[0].Data), "%PDF-") {
					t.Fatal("missing paid invoice confirmation or PDF")
				}
				if fail {
					return errors.New("provider unavailable")
				}
				return nil
			})
			handler.RunInvoiceEmails(ctx)
			if calls != 1 || !repo.finished || repo.delivered == fail {
				t.Fatalf("calls=%d finished=%v delivered=%v", calls, repo.finished, repo.delivered)
			}
		})
	}
}

func (repo *invoiceTestRepository) CreatePlanInvoice(_ context.Context, user, plan, key, currency string, _ time.Time) (*db.Invoice, error) {
	repo.created = true
	repo.invoice.UserID = user
	repo.invoice.PlanID = plan
	repo.invoice.Currency = currency
	return &repo.invoice, nil
}
func (repo *invoiceTestRepository) InvoiceForUser(_ context.Context, user, id string) (*db.Invoice, error) {
	if user != repo.invoice.UserID || id != repo.invoice.ID {
		return nil, db.ErrNotFound
	}
	return &repo.invoice, nil
}
func (repo *invoiceTestRepository) PayInvoiceCredit(_ context.Context, user, id string, _ time.Time) error {
	if user != repo.invoice.UserID || id != repo.invoice.ID {
		return db.ErrNotFound
	}
	repo.paid = true
	return repo.purchaseErr
}

func TestInvoiceCreateReadPDFAndPaymentBoundaries(t *testing.T) {
	const owner = "11111111-1111-4111-8111-111111111111"
	const id = "22222222-2222-4222-8222-222222222222"
	repo := &invoiceTestRepository{entitlementRepository: &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}}, invoice: db.Invoice{ID: id, UserID: owner, Kind: "plan", Status: "pending", Name: "<script>plan</script>", Email: "buyer@example.com", Credits: 10, AmountMinor: 1000, Currency: "USD", ExpiresAt: time.Now().Add(time.Hour)}}
	handler := newTestHandler(t, repo, &memoryStorage{objects: make(map[string][]byte)})
	var err error
	handler.templates, err = parseTemplates(os.DirFS("../.."), config.BrandingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Get("/invoices/{id}", handler.Invoice)
	router.Get("/invoices/{id}/pdf", handler.InvoicePDF)
	router.Post("/invoices/{id}/pay", handler.PayInvoice)
	router.Post("/create/{id}", handler.CreateInvoice)
	call := func(method, path, user, form string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(form))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: &db.User{ID: user}, Transport: transportCookie, Claims: &appauth.Claims{CSRF: "expected"}}))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	for _, path := range []string{"/invoices/" + id, "/invoices/" + id + "/pdf"} {
		response := call("GET", path, "other", "")
		if response.Code != 404 {
			t.Fatalf("cross-account %s: %d", path, response.Code)
		}
	}
	response := call("POST", "/create/"+id, owner, "csrf_token=expected&credit_request_id=33333333-3333-4333-8333-333333333333")
	if response.Code != 303 || !repo.created || repo.paid {
		t.Fatalf("invoice creation must not pay: %d", response.Code)
	}
	response = call("GET", "/invoices/"+id, owner, "")
	if response.Code != 200 || strings.Contains(response.Body.String(), "<script>plan</script>") || !strings.Contains(response.Body.String(), "&lt;script&gt;") || response.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("invoice page: %d %s", response.Code, response.Body.String())
	}
	response = call("GET", "/invoices/"+id+"/pdf", owner, "")
	if response.Code != 200 || response.Header().Get("Content-Type") != "application/pdf" || !strings.HasPrefix(response.Body.String(), "%PDF-") {
		t.Fatalf("PDF: %d", response.Code)
	}
	response = call("POST", "/invoices/"+id+"/pay", owner, "gateway=credit")
	if response.Code != http.StatusForbidden || repo.paid {
		t.Fatal("missing CSRF paid invoice")
	}
	response = call("POST", "/invoices/"+id+"/pay", "other", "gateway=credit&csrf_token=expected")
	if response.Code != 404 || repo.paid {
		t.Fatal("cross-account payment")
	}
	repo.purchaseErr = db.ErrInsufficientCredit
	response = call("POST", "/invoices/"+id+"/pay", owner, "gateway=credit&csrf_token=expected")
	if response.Code != http.StatusPaymentRequired {
		t.Fatalf("insufficient credit: %d", response.Code)
	}
}

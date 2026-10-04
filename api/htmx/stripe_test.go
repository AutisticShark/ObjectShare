package htmx

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/go-chi/chi/v5"
)

func TestStripeSignatureVerificationRejectsTamperingAndStaleEvents(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	payload, secret := []byte(`{"id":"evt_1"}`), "whsec_test"
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte("1788523200."))
	_, _ = mac.Write(payload)
	header := "t=1788523200,v1=" + hex.EncodeToString(mac.Sum(nil))
	if !verifyStripeSignature(payload, header, secret, now) {
		t.Fatal("valid signature was rejected")
	}
	if verifyStripeSignature([]byte(`{"id":"evt_2"}`), header, secret, now) {
		t.Fatal("tampered payload was accepted")
	}
	if verifyStripeSignature(payload, header, secret, now.Add(6*time.Minute)) {
		t.Fatal("stale signature was accepted")
	}
}

func TestVerifiedStripeWebhookAppliesServerMappedPlan(t *testing.T) {
	userID := "11111111-1111-4111-8111-111111111111"
	planID := "22222222-2222-4222-8222-222222222222"
	now := time.Now().UTC()
	repository := &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}, plan: &db.PaidPlan{ID: planID, Gateway: db.BillingGatewayStripe, GatewayPlanID: "price_plus"}}
	handler := newTestHandler(t, repository, &memoryStorage{objects: make(map[string][]byte)})
	handler.billingGateways = map[string]billingGateway{db.BillingGatewayStripe: newStripeClient(config.StripeBillingConfig{Enabled: true, WebhookSecret: "whsec_test"})}
	payload := []byte(fmt.Sprintf(`{"id":"evt_1","type":"customer.subscription.updated","created":%d,"data":{"object":{"id":"sub_1","customer":"cus_1","status":"active","current_period_end":%d,"cancel_at_period_end":false,"metadata":{"user_id":"%s"},"items":{"data":[{"price":{"id":"price_plus"}}]}}}}`, now.Unix(), now.Add(30*24*time.Hour).Unix(), userID))
	mac := hmac.New(sha256.New, []byte("whsec_test"))
	_, _ = fmt.Fprintf(mac, "%d.", now.Unix())
	_, _ = mac.Write(payload)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/billing/stripe/webhook", bytes.NewReader(payload))
	request.Header.Set("Stripe-Signature", fmt.Sprintf("t=%d,v1=%s", now.Unix(), hex.EncodeToString(mac.Sum(nil))))
	response := httptest.NewRecorder()
	handler.StripeWebhook(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	if repository.applied == nil || repository.applied.UserID != userID || repository.applied.PlanID != planID || repository.applied.Status != "active" {
		t.Fatalf("webhook update=%#v", repository.applied)
	}
}

func TestVerifiedStripeWebhookAppliesOnlyPaidMatchingTopUp(t *testing.T) {
	topUpID := "33333333-3333-4333-8333-333333333333"
	now := time.Now().UTC().Truncate(time.Second)
	repository := &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}}
	handler := newTestHandler(t, repository, &memoryStorage{objects: make(map[string][]byte)})
	handler.billingGateways = map[string]billingGateway{db.BillingGatewayStripe: newStripeClient(config.StripeBillingConfig{Enabled: true, WebhookSecret: "whsec_test"})}
	payload := []byte(fmt.Sprintf(`{"id":"evt_topup","type":"checkout.session.completed","created":%d,"data":{"object":{"id":"cs_1","mode":"payment","payment_status":"paid","payment_intent":"pi_1","amount_total":2500,"currency":"usd","metadata":{"purpose":"credit_topup","topup_id":"%s"}}}}`, now.Unix(), topUpID))
	mac := hmac.New(sha256.New, []byte("whsec_test"))
	_, _ = fmt.Fprintf(mac, "%d.", now.Unix())
	_, _ = mac.Write(payload)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/billing/stripe/webhook", bytes.NewReader(payload))
	request.Header.Set("Stripe-Signature", fmt.Sprintf("t=%d,v1=%s", now.Unix(), hex.EncodeToString(mac.Sum(nil))))
	response := httptest.NewRecorder()
	handler.StripeWebhook(response, request)
	if response.Code != http.StatusNoContent || repository.creditPayment == nil {
		t.Fatalf("status=%d payment=%#v body=%q", response.Code, repository.creditPayment, response.Body.String())
	}
	if repository.creditPayment.TopUpID != topUpID || repository.creditPayment.GatewayPaymentID != "pi_1" || repository.creditPayment.AmountMinor != 2500 || repository.creditPayment.Currency != "usd" {
		t.Fatalf("credit payment=%#v", repository.creditPayment)
	}

	repository.creditPayment = nil
	unpaid := bytes.Replace(payload, []byte(`"payment_status":"paid"`), []byte(`"payment_status":"unpaid"`), 1)
	mac = hmac.New(sha256.New, []byte("whsec_test"))
	_, _ = fmt.Fprintf(mac, "%d.", now.Unix())
	_, _ = mac.Write(unpaid)
	request = httptest.NewRequest(http.MethodPost, "/api/v1/billing/stripe/webhook", bytes.NewReader(unpaid))
	request.Header.Set("Stripe-Signature", fmt.Sprintf("t=%d,v1=%s", now.Unix(), hex.EncodeToString(mac.Sum(nil))))
	response = httptest.NewRecorder()
	handler.StripeWebhook(response, request)
	if response.Code != http.StatusNoContent || repository.creditPayment != nil {
		t.Fatalf("unpaid status=%d payment=%#v", response.Code, repository.creditPayment)
	}
}

func TestStripeClientCreatesServerPricedTopUp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/checkout/sessions" || request.Header.Get("Authorization") != "Bearer sk_test" || request.Header.Get("Idempotency-Key") != "objectshare-topup-33333333-3333-4333-8333-333333333333" {
			t.Errorf("unexpected request: %s headers=%v", request.URL.Path, request.Header)
		}
		if err := request.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if request.FormValue("mode") != "payment" || request.FormValue("line_items[0][price_data][currency]") != "usd" || request.FormValue("line_items[0][price_data][unit_amount]") != "2500" || request.FormValue("metadata[topup_id]") != "33333333-3333-4333-8333-333333333333" {
			t.Errorf("unexpected top-up form: %v", request.Form)
		}
		_, _ = io.WriteString(writer, `{"url":"https://checkout.stripe.com/c/pay/cs_test_1"}`)
	}))
	defer server.Close()
	client := &stripeClient{secret: "sk_test", apiBase: server.URL, client: server.Client()}
	result, err := client.TopUp(t.Context(), billingTopUpInput{TopUpID: "33333333-3333-4333-8333-333333333333", Credits: 25, AmountMinor: 2500, Currency: "USD", SuccessURL: "https://share.example.com/account", CancelURL: "https://share.example.com/account"})
	if err != nil || result.Location != "https://checkout.stripe.com/c/pay/cs_test_1" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

// A Checkout Session must stop accepting payment when the invoice's payment
// window ends; otherwise a customer could pay hours later for an invoice that
// can no longer be applied. Stripe cannot create a session shorter than 30
// minutes, so a nearly expired invoice must not start one.
func TestStripeInvoiceCheckoutExpiresWithTheInvoice(t *testing.T) {
	const owner, id = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	var sessions []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if err := request.ParseForm(); err != nil {
			t.Error(err)
		}
		sessions = append(sessions, request.FormValue("expires_at"))
		_, _ = io.WriteString(writer, `{"url":"https://checkout.stripe.com/c/pay/cs_test_1"}`)
	}))
	defer server.Close()
	repo := &checkoutRetryRepository{invoiceTestRepository: &invoiceTestRepository{entitlementRepository: &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}}}}
	handler := newTestHandler(t, repo, &memoryStorage{objects: make(map[string][]byte)})
	handler.config.Billing = &config.BillingConfig{PublicURL: "https://share.example.com", CreditCurrency: "USD"}
	handler.billingGateways = map[string]billingGateway{db.BillingGatewayStripe: &stripeClient{secret: "sk_test", apiBase: server.URL, client: server.Client()}}
	router := chi.NewRouter()
	router.Post("/invoices/{id}/pay", handler.PayInvoice)
	pay := func(remaining time.Duration, bound string) *httptest.ResponseRecorder {
		expires := time.Now().UTC().Add(remaining).Truncate(time.Second)
		repo.invoice = db.Invoice{ID: id, UserID: owner, Kind: "plan", Name: "Plus", Email: "buyer@example.com", Credits: 10, AmountMinor: 1000, Currency: "USD", Status: "pending", Gateway: bound, ExpiresAt: expires}
		repo.payment = db.CreditTopUp{ID: id, UserID: owner, Gateway: db.BillingGatewayStripe, Credits: 10, AmountMinor: 1000, Currency: "USD", Status: db.CreditTopUpPending, ExpiresAt: expires, CreatedAt: time.Now().UTC()}
		request := httptest.NewRequest(http.MethodPost, "/invoices/"+id+"/pay", strings.NewReader("gateway=stripe"))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: &db.User{ID: owner}, Transport: transportBearer}))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}

	response := pay(time.Hour, "")
	if response.Code != http.StatusSeeOther || len(sessions) != 1 || sessions[0] != strconv.FormatInt(repo.invoice.ExpiresAt.Unix(), 10) {
		t.Fatalf("status=%d expires_at=%q, want the invoice expiry %d", response.Code, sessions, repo.invoice.ExpiresAt.Unix())
	}
	response = pay(20*time.Minute, "")
	if response.Code != http.StatusConflict || len(sessions) != 1 {
		t.Fatalf("checkout started with 20 minutes left: status=%d sessions=%d", response.Code, len(sessions))
	}
	// An invoice already bound to Stripe (a retry after a lost response) is
	// refused by the client instead of asking Stripe for an invalid session.
	response = pay(20*time.Minute, db.BillingGatewayStripe)
	if response.Code != http.StatusConflict || len(sessions) != 1 {
		t.Fatalf("retry started with 20 minutes left: status=%d sessions=%d", response.Code, len(sessions))
	}
}

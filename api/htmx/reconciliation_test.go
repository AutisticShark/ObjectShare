package htmx

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/go-chi/chi/v5/middleware"
)

func capturedPaymentHandler(t *testing.T, repository *entitlementRepository, gateways map[string]billingGateway) (*Handler, *bytes.Buffer) {
	t.Helper()
	handler := newTestHandler(t, repository, &memoryStorage{objects: make(map[string][]byte)})
	handler.billingGateways = gateways
	logs := new(bytes.Buffer)
	handler.logger = slog.New(slog.NewTextHandler(logs, nil))
	return handler, logs
}

func TestStripeCapturedPaymentThatCannotBeAppliedIsLoggedAndRecorded(t *testing.T) {
	topUpID := "33333333-3333-4333-8333-333333333333"
	now := time.Now().UTC().Truncate(time.Second)
	repository := &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}, applyErr: db.ErrConflict}
	handler, logs := capturedPaymentHandler(t, repository, map[string]billingGateway{db.BillingGatewayStripe: newStripeClient(config.StripeBillingConfig{Enabled: true, WebhookSecret: "whsec_test"})})
	payload := []byte(fmt.Sprintf(`{"id":"evt_topup","type":"checkout.session.completed","created":%d,"data":{"object":{"id":"cs_1","mode":"payment","payment_status":"paid","payment_intent":"pi_captured","amount_total":2500,"currency":"usd","metadata":{"purpose":"credit_topup","topup_id":"%s"}}}}`, now.Unix(), topUpID))
	mac := hmac.New(sha256.New, []byte("whsec_test"))
	_, _ = fmt.Fprintf(mac, "%d.", now.Unix())
	_, _ = mac.Write(payload)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/billing/stripe/webhook", bytes.NewReader(payload))
	request.Header.Set("Stripe-Signature", fmt.Sprintf("t=%d,v1=%s", now.Unix(), hex.EncodeToString(mac.Sum(nil))))
	response := httptest.NewRecorder()
	handler.StripeWebhook(response, request)

	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 so Stripe retries and shows the failure", response.Code)
	}
	if len(repository.reconciled) != 1 || repository.reconciled[0].GatewayPaymentID != "pi_captured" || repository.reconciled[0].Gateway != db.BillingGatewayStripe || repository.reconciled[0].AmountMinor != 2500 || repository.reconciled[0].TopUpID != topUpID {
		t.Fatalf("reconciliation records = %#v", repository.reconciled)
	}
	if out := logs.String(); !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "pi_captured") || !strings.Contains(out, "manual reconciliation") {
		t.Fatalf("no error log with the payment id: %q", out)
	}
}

func TestPayPalCaptureWebhookThatCannotBeAppliedIsLoggedAndRecorded(t *testing.T) {
	topUpID := "33333333-3333-4333-8333-333333333333"
	now := time.Now().UTC().Truncate(time.Second)
	repository := &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}, applyErr: db.ErrNotFound}
	handler, logs := capturedPaymentHandler(t, repository, map[string]billingGateway{db.BillingGatewayPayPal: &paypalGatewayStub{verified: true}})
	payload := `{"id":"WH-1","event_type":"PAYMENT.CAPTURE.COMPLETED","create_time":"` + now.Format(time.RFC3339) + `","resource":{"id":"CAPTURE-9","custom_id":"` + topUpID + `","status":"COMPLETED","amount":{"currency_code":"USD","value":"25.00"}}}`
	response := httptest.NewRecorder()
	handler.PayPalWebhook(response, httptest.NewRequest(http.MethodPost, "/api/v1/billing/paypal/webhook", strings.NewReader(payload)))
	if response.Code != http.StatusUnprocessableEntity || len(repository.reconciled) != 1 || repository.reconciled[0].GatewayPaymentID != "CAPTURE-9" {
		t.Fatalf("status=%d records=%#v", response.Code, repository.reconciled)
	}
	if !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "CAPTURE-9") {
		t.Fatalf("no error log with the payment id: %q", logs.String())
	}
}

func TestPayPalReturnNeverTellsAChargedCustomerTheCaptureIsInvalid(t *testing.T) {
	topUpID, orderID := "33333333-3333-4333-8333-333333333333", "ORDER-EXPECTED"
	for name, capture := range map[string]paypalCapture{
		"mismatched top-up id": {ID: "CAPTURE-1", CustomID: "another-top-up", Status: "COMPLETED", Amount: paypalAmount{Currency: "USD", Value: "25.00"}},
		"unparsable amount":    {ID: "CAPTURE-1", CustomID: topUpID, Status: "COMPLETED", Amount: paypalAmount{Currency: "USD", Value: "not money"}},
	} {
		t.Run(name, func(t *testing.T) {
			repository := &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}, topUp: &db.CreditTopUp{
				ID: topUpID, Gateway: db.BillingGatewayPayPal, GatewayReference: &orderID, Status: db.CreditTopUpPending,
			}}
			handler, logs := capturedPaymentHandler(t, repository, map[string]billingGateway{db.BillingGatewayPayPal: &paypalGatewayStub{capture: capture}})
			response := httptest.NewRecorder()
			handler.PayPalTopUpReturn(response, httptest.NewRequest(http.MethodGet, "/billing/paypal/topup/return?topup="+topUpID+"&token="+orderID, nil))
			body := response.Body.String()
			if strings.Contains(body, "does not match") || !strings.Contains(body, "CAPTURE-1") || !strings.Contains(body, "do not pay again") {
				t.Fatalf("customer message = %q", body)
			}
			if len(repository.reconciled) != 1 || repository.reconciled[0].GatewayPaymentID != "CAPTURE-1" || !strings.Contains(logs.String(), "level=ERROR") {
				t.Fatalf("records=%#v logs=%q", repository.reconciled, logs.String())
			}
		})
	}
	// An uncaptured order is still reported as a mismatch and creates no record.
	repository := &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}, topUp: &db.CreditTopUp{
		ID: topUpID, Gateway: db.BillingGatewayPayPal, GatewayReference: &orderID, Status: db.CreditTopUpPending,
	}}
	handler, _ := capturedPaymentHandler(t, repository, map[string]billingGateway{db.BillingGatewayPayPal: &paypalGatewayStub{capture: paypalCapture{ID: "", CustomID: topUpID, Status: "PENDING"}}})
	response := httptest.NewRecorder()
	handler.PayPalTopUpReturn(response, httptest.NewRequest(http.MethodGet, "/billing/paypal/topup/return?topup="+topUpID+"&token="+orderID, nil))
	if response.Code != http.StatusUnprocessableEntity || len(repository.reconciled) != 0 {
		t.Fatalf("uncaptured order: status=%d records=%#v", response.Code, repository.reconciled)
	}
}

func TestStreamErrorsAreLoggedUnlessTheClientLeft(t *testing.T) {
	logs := new(bytes.Buffer)
	handler := &Handler{logger: slog.New(slog.NewTextHandler(logs, nil))}
	failing := func() error { return errors.New("storage read failed") }

	handler.logStreamError(httptest.NewRequest(http.MethodGet, "/file", nil), "file-1", "stream download", failing)
	if out := logs.String(); !strings.Contains(out, "file-1") || !strings.Contains(out, "storage read failed") || !strings.Contains(out, "level=WARN") {
		t.Fatalf("a failed stream was not logged: %q", out)
	}

	logs.Reset()
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	handler.logStreamError(httptest.NewRequest(http.MethodGet, "/file", nil).WithContext(gone), "file-2", "stream download", failing)
	handler.logStreamError(httptest.NewRequest(http.MethodGet, "/file", nil), "file-3", "stream download", func() error { return nil })
	if logs.Len() != 0 {
		t.Fatalf("routine disconnects or successful copies were logged: %q", logs.String())
	}
}

func TestInternalErrorLogsTheRequestIDFromContext(t *testing.T) {
	logs := new(bytes.Buffer)
	handler := &Handler{logger: slog.New(slog.NewTextHandler(logs, nil))}
	var response *httptest.ResponseRecorder
	chain := middleware.RequestID(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		handler.internalError(writer, request, "load thing", errors.New("boom"))
	}))
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Request-Id", "req-from-proxy-7")
	response = httptest.NewRecorder()
	chain.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError || !strings.Contains(logs.String(), "request_id=req-from-proxy-7") {
		t.Fatalf("status=%d log=%q", response.Code, logs.String())
	}
	generated := httptest.NewRecorder()
	chain.ServeHTTP(generated, httptest.NewRequest(http.MethodGet, "/", nil))
	if strings.Contains(logs.String(), "request_id= ") || strings.Contains(logs.String(), `request_id=""`) {
		t.Fatalf("a generated request id was not logged: %q", logs.String())
	}
}

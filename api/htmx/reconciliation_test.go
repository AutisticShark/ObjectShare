package htmx

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
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

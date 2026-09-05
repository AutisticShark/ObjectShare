package htmx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
)

type paypalGatewayStub struct {
	verified     bool
	details      paypalSubscription
	detailCalls  int
	capture      paypalCapture
	captureCalls int
}

func (*paypalGatewayStub) TopUp(context.Context, billingTopUpInput) (billingTopUpResult, error) {
	return billingTopUpResult{Location: "https://www.sandbox.paypal.com/approve", GatewayReference: "ORDER-1"}, nil
}
func (stub *paypalGatewayStub) Portal(context.Context, *db.Subscription, string) (string, error) {
	return "https://www.sandbox.paypal.com/myaccount/autopay/connect/", nil
}
func (stub *paypalGatewayStub) VerifyWebhook(context.Context, http.Header, json.RawMessage) (bool, error) {
	return stub.verified, nil
}
func (stub *paypalGatewayStub) SubscriptionDetails(context.Context, string) (paypalSubscription, error) {
	stub.detailCalls++
	return stub.details, nil
}
func (stub *paypalGatewayStub) CaptureTopUp(context.Context, string) (paypalCapture, error) {
	stub.captureCalls++
	return stub.capture, nil
}

func TestVerifiedPayPalWebhookAppliesServerMappedPlan(t *testing.T) {
	userID := "11111111-1111-4111-8111-111111111111"
	planID := "22222222-2222-4222-8222-222222222222"
	now := time.Now().UTC().Truncate(time.Second)
	repository := &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}, plan: &db.PaidPlan{
		ID: planID, Gateway: db.BillingGatewayPayPal, GatewayPlanID: "P-ABCDEFGHIJKLMNOPQRSTUVWX",
	}}
	handler := newTestHandler(t, repository, &memoryStorage{objects: make(map[string][]byte)})
	handler.billingGateways = map[string]billingGateway{db.BillingGatewayPayPal: &paypalGatewayStub{verified: true}}
	payload := `{"id":"WH-1","event_type":"BILLING.SUBSCRIPTION.ACTIVATED","create_time":"` + now.Format(time.RFC3339) + `","resource":{"id":"I-SUBSCRIPTION","plan_id":"P-ABCDEFGHIJKLMNOPQRSTUVWX","custom_id":"` + userID + `","status":"ACTIVE","subscriber":{"payer_id":"PAYER1"},"billing_info":{"next_billing_time":"` + now.Add(30*24*time.Hour).Format(time.RFC3339) + `"}}}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/billing/paypal/webhook", strings.NewReader(payload))
	response := httptest.NewRecorder()
	handler.PayPalWebhook(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	if repository.applied == nil || repository.applied.Gateway != db.BillingGatewayPayPal || repository.applied.UserID != userID || repository.applied.PlanID != planID || repository.applied.Status != "active" || repository.applied.SubscriptionID != "I-SUBSCRIPTION" {
		t.Fatalf("webhook update=%#v", repository.applied)
	}
}

func TestPayPalWebhookRejectsUnverifiedEvent(t *testing.T) {
	repository := &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}}
	handler := newTestHandler(t, repository, &memoryStorage{objects: make(map[string][]byte)})
	handler.billingGateways = map[string]billingGateway{db.BillingGatewayPayPal: &paypalGatewayStub{}}
	payload := `{"id":"WH-1","event_type":"BILLING.SUBSCRIPTION.ACTIVATED","create_time":"2026-09-05T00:00:00Z","resource":{"id":"I-SUBSCRIPTION"}}`
	response := httptest.NewRecorder()
	handler.PayPalWebhook(response, httptest.NewRequest(http.MethodPost, "/api/v1/billing/paypal/webhook", strings.NewReader(payload)))
	if response.Code != http.StatusBadRequest || repository.applied != nil {
		t.Fatalf("status=%d update=%#v", response.Code, repository.applied)
	}
}

func TestVerifiedPayPalWebhookAppliesCompletedTopUp(t *testing.T) {
	topUpID := "33333333-3333-4333-8333-333333333333"
	now := time.Now().UTC().Truncate(time.Second)
	repository := &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}}
	handler := newTestHandler(t, repository, &memoryStorage{objects: make(map[string][]byte)})
	handler.billingGateways = map[string]billingGateway{db.BillingGatewayPayPal: &paypalGatewayStub{verified: true}}
	payload := `{"id":"WH-TOPUP","event_type":"PAYMENT.CAPTURE.COMPLETED","create_time":"` + now.Format(time.RFC3339) + `","resource":{"id":"CAPTURE-1","custom_id":"` + topUpID + `","status":"COMPLETED","amount":{"currency_code":"USD","value":"25.00"}}}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/billing/paypal/webhook", strings.NewReader(payload))
	response := httptest.NewRecorder()
	handler.PayPalWebhook(response, request)
	if response.Code != http.StatusNoContent || repository.creditPayment == nil {
		t.Fatalf("status=%d payment=%#v body=%q", response.Code, repository.creditPayment, response.Body.String())
	}
	if repository.creditPayment.TopUpID != topUpID || repository.creditPayment.GatewayPaymentID != "CAPTURE-1" || repository.creditPayment.AmountMinor != 2500 || repository.creditPayment.Currency != "USD" {
		t.Fatalf("payment=%#v", repository.creditPayment)
	}
}

func TestPayPalTopUpReturnRejectsForgedOrderBeforeCapture(t *testing.T) {
	topUpID, expectedOrder := "33333333-3333-4333-8333-333333333333", "ORDER-EXPECTED"
	repository := &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}, topUp: &db.CreditTopUp{
		ID: topUpID, Gateway: db.BillingGatewayPayPal, GatewayReference: &expectedOrder, Status: db.CreditTopUpPending,
	}}
	gateway := &paypalGatewayStub{}
	handler := newTestHandler(t, repository, &memoryStorage{objects: make(map[string][]byte)})
	handler.billingGateways = map[string]billingGateway{db.BillingGatewayPayPal: gateway}
	response := httptest.NewRecorder()
	handler.PayPalTopUpReturn(response, httptest.NewRequest(http.MethodGet, "/billing/paypal/topup/return?topup="+topUpID+"&token=ORDER-FORGED", nil))
	if response.Code != http.StatusUnprocessableEntity || gateway.captureCalls != 0 || repository.creditPayment != nil {
		t.Fatalf("status=%d captureCalls=%d payment=%#v", response.Code, gateway.captureCalls, repository.creditPayment)
	}
}

func TestPayPalTopUpReturnCapturesMatchingPendingOrder(t *testing.T) {
	topUpID, orderID := "33333333-3333-4333-8333-333333333333", "ORDER-EXPECTED"
	repository := &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}, topUp: &db.CreditTopUp{
		ID: topUpID, Gateway: db.BillingGatewayPayPal, GatewayReference: &orderID, Status: db.CreditTopUpPending,
	}}
	gateway := &paypalGatewayStub{capture: paypalCapture{ID: "CAPTURE-1", CustomID: topUpID, Status: "COMPLETED", Amount: paypalAmount{Currency: "USD", Value: "25.00"}}}
	handler := newTestHandler(t, repository, &memoryStorage{objects: make(map[string][]byte)})
	handler.billingGateways = map[string]billingGateway{db.BillingGatewayPayPal: gateway}
	response := httptest.NewRecorder()
	handler.PayPalTopUpReturn(response, httptest.NewRequest(http.MethodGet, "/billing/paypal/topup/return?topup="+topUpID+"&token="+orderID, nil))
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/account?message=topup-complete" || gateway.captureCalls != 1 || repository.creditPayment == nil {
		t.Fatalf("status=%d location=%q captureCalls=%d payment=%#v", response.Code, response.Header().Get("Location"), gateway.captureCalls, repository.creditPayment)
	}
	if repository.creditPayment.GatewayPaymentID != "CAPTURE-1" || repository.creditPayment.AmountMinor != 2500 || repository.creditPayment.Currency != "USD" {
		t.Fatalf("payment=%#v", repository.creditPayment)
	}
}

func TestPayPalPaymentFailureUsesCurrentSubscriptionState(t *testing.T) {
	userID := "11111111-1111-4111-8111-111111111111"
	now := time.Now().UTC().Truncate(time.Second)
	repository := &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}, plan: &db.PaidPlan{ID: "22222222-2222-4222-8222-222222222222"}}
	details := paypalSubscription{ID: "I-SUBSCRIPTION", PlanID: "P-ABCDEFGHIJKLMNOPQRSTUVWX", CustomID: userID, Status: "ACTIVE"}
	details.BillingInfo.NextBillingTime = now.Add(24 * time.Hour).Format(time.RFC3339)
	gateway := &paypalGatewayStub{verified: true, details: details}
	handler := newTestHandler(t, repository, &memoryStorage{objects: make(map[string][]byte)})
	handler.billingGateways = map[string]billingGateway{db.BillingGatewayPayPal: gateway}
	payload := `{"id":"WH-FAILED","event_type":"BILLING.SUBSCRIPTION.PAYMENT.FAILED","create_time":"` + now.Format(time.RFC3339) + `","resource":{"id":"I-SUBSCRIPTION"}}`
	response := httptest.NewRecorder()
	handler.PayPalWebhook(response, httptest.NewRequest(http.MethodPost, "/api/v1/billing/paypal/webhook", strings.NewReader(payload)))
	if response.Code != http.StatusNoContent || gateway.detailCalls != 1 || repository.applied == nil || repository.applied.Status != "active" {
		t.Fatalf("status=%d detail calls=%d update=%#v body=%q", response.Code, gateway.detailCalls, repository.applied, response.Body.String())
	}
}

func TestPayPalClientUsesOAuthAndReturnsOnlyPayPalApprovalURL(t *testing.T) {
	tokenCalls, checkoutCalls := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/oauth2/token":
			tokenCalls++
			clientID, secret, ok := request.BasicAuth()
			if !ok || clientID != "client" || secret != "secret" {
				t.Errorf("invalid OAuth credentials")
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"access_token":"token","expires_in":3600}`)
		case "/v2/checkout/orders":
			checkoutCalls++
			if request.Header.Get("Authorization") != "Bearer token" || request.Header.Get("PayPal-Request-Id") == "" {
				t.Errorf("missing authenticated or idempotent request headers")
			}
			var body map[string]any
			if json.NewDecoder(request.Body).Decode(&body) != nil || body["intent"] != "CAPTURE" {
				t.Errorf("unexpected checkout body: %#v", body)
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"id":"ORDER-1","links":[{"rel":"approve","href":"https://www.sandbox.paypal.com/checkoutnow?token=ORDER-1"}]}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client := &paypalClient{settings: config.PayPalBillingConfig{Environment: "sandbox", ClientID: "client", ClientSecret: "secret"}, apiBase: server.URL, webBase: "https://www.sandbox.paypal.com", client: server.Client()}
	input := billingTopUpInput{TopUpID: "topup-1", Currency: "USD", Credits: 10, AmountMinor: 1000, UserID: "11111111-1111-4111-8111-111111111111", Email: "user@example.com", SuccessURL: "https://share.example.com/account", CancelURL: "https://share.example.com/plans"}
	for range 2 {
		result, err := client.TopUp(t.Context(), input)
		location := result.Location
		if err != nil || !strings.HasPrefix(location, "https://www.sandbox.paypal.com/") {
			t.Fatalf("location=%q err=%v", location, err)
		}
	}
	if tokenCalls != 1 || checkoutCalls != 2 {
		t.Fatalf("token calls=%d checkout calls=%d", tokenCalls, checkoutCalls)
	}
	if client.safeBrowserURL("https://attacker.example/approve") || client.safeBrowserURL("http://www.sandbox.paypal.com/approve") {
		t.Fatal("unsafe PayPal approval URL was accepted")
	}
}

func TestPayPalClientCreatesAndCapturesServerPricedTopUp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/oauth2/token":
			_, _ = io.WriteString(writer, `{"access_token":"token","expires_in":3600}`)
		case "/v2/checkout/orders":
			var body struct {
				Intent        string `json:"intent"`
				PurchaseUnits []struct {
					CustomID string       `json:"custom_id"`
					Amount   paypalAmount `json:"amount"`
				} `json:"purchase_units"`
			}
			if json.NewDecoder(request.Body).Decode(&body) != nil || body.Intent != "CAPTURE" || len(body.PurchaseUnits) != 1 || body.PurchaseUnits[0].CustomID != "33333333-3333-4333-8333-333333333333" || body.PurchaseUnits[0].Amount != (paypalAmount{Currency: "USD", Value: "25.00"}) {
				t.Errorf("unexpected order body: %#v", body)
			}
			_, _ = io.WriteString(writer, `{"id":"ORDER-1","links":[{"rel":"payer-action","href":"https://www.sandbox.paypal.com/checkoutnow?token=ORDER-1"}]}`)
		case "/v2/checkout/orders/ORDER-1/capture":
			if request.Header.Get("Prefer") != "return=representation" || request.Header.Get("PayPal-Request-Id") != "capture-ORDER-1" {
				t.Error("capture omitted representation or idempotency header")
			}
			_, _ = io.WriteString(writer, `{"id":"ORDER-1","status":"COMPLETED","purchase_units":[{"payments":{"captures":[{"id":"CAPTURE-1","custom_id":"33333333-3333-4333-8333-333333333333","status":"COMPLETED","amount":{"currency_code":"USD","value":"25.00"}}]}}]}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client := &paypalClient{settings: config.PayPalBillingConfig{Environment: "sandbox", ClientID: "client", ClientSecret: "secret"}, apiBase: server.URL, webBase: "https://www.sandbox.paypal.com", client: server.Client()}
	result, err := client.TopUp(t.Context(), billingTopUpInput{TopUpID: "33333333-3333-4333-8333-333333333333", Credits: 25, AmountMinor: 2500, Currency: "USD", SuccessURL: "https://share.example.com/return", CancelURL: "https://share.example.com/account"})
	if err != nil || result.GatewayReference != "ORDER-1" || !strings.HasPrefix(result.Location, "https://www.sandbox.paypal.com/") {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	capture, err := client.CaptureTopUp(t.Context(), "ORDER-1")
	if err != nil || capture.ID != "CAPTURE-1" || capture.CustomID != "33333333-3333-4333-8333-333333333333" {
		t.Fatalf("capture=%#v err=%v", capture, err)
	}
}

func TestPayPalCaptureRetryRequiresCompletedOrder(t *testing.T) {
	for _, status := range []string{"COMPLETED", "APPROVED"} {
		t.Run(status, func(t *testing.T) {
			reads := 0
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Header.Get("Authorization") != "Bearer cached-token" {
					t.Error("order lookup was not authenticated")
				}
				if request.Method == http.MethodPost && request.URL.Path == "/v2/checkout/orders/ORDER-1/capture" {
					http.Error(writer, "already captured", http.StatusUnprocessableEntity)
					return
				}
				if request.Method != http.MethodGet || request.URL.Path != "/v2/checkout/orders/ORDER-1" {
					http.NotFound(writer, request)
					return
				}
				reads++
				_, _ = fmt.Fprintf(writer, `{"id":"ORDER-1","status":%q,"purchase_units":[{"payments":{"captures":[{"id":"CAPTURE-1","custom_id":"33333333-3333-4333-8333-333333333333","status":"COMPLETED","amount":{"currency_code":"USD","value":"25.00"}}]}}]}`, status)
			}))
			defer server.Close()
			client := &paypalClient{apiBase: server.URL, client: server.Client(), token: "cached-token", expires: time.Now().Add(time.Hour)}
			capture, err := client.CaptureTopUp(t.Context(), "ORDER-1")
			if reads != 1 || (status == "COMPLETED" && (err != nil || capture.ID != "CAPTURE-1")) || (status != "COMPLETED" && err == nil) {
				t.Fatalf("reads=%d capture=%#v err=%v", reads, capture, err)
			}
		})
	}
}

func TestPayPalAmountsUseExactUnsignedDecimalValues(t *testing.T) {
	for _, value := range []string{"", "25", "25.0", "25.000", "+25.00", "25.+1", "-0.01", " 25.00", "1e2.00", "92233720368547759.00"} {
		if amount, err := parseMinorAmount(value); err == nil {
			t.Errorf("accepted %q as %d", value, amount)
		}
	}
	for value, expected := range map[string]int64{"0.00": 0, "25.00": 2500, "123.45": 12345, "92233720368547758.07": 9223372036854775807} {
		if amount, err := parseMinorAmount(value); err != nil || amount != expected {
			t.Errorf("%q = %d, %v; want %d", value, amount, err, expected)
		}
	}
}

func TestPayPalSignatureVerificationSendsWebhookEventAsJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			WebhookID    string         `json:"webhook_id"`
			WebhookEvent map[string]any `json:"webhook_event"`
		}
		if json.NewDecoder(request.Body).Decode(&body) != nil || body.WebhookID != "WH-CONFIGURED" || body.WebhookEvent["id"] != "WH-EVENT" {
			t.Errorf("unexpected verification body: %#v", body)
		}
		_, _ = io.WriteString(writer, `{"verification_status":"SUCCESS"}`)
	}))
	defer server.Close()
	client := &paypalClient{settings: config.PayPalBillingConfig{WebhookID: "WH-CONFIGURED"}, apiBase: server.URL, client: server.Client(), token: "cached", expires: time.Now().Add(time.Hour)}
	headers := http.Header{
		"Paypal-Auth-Algo": {"SHA256withRSA"}, "Paypal-Cert-Url": {"https://api.paypal.com/cert.pem"},
		"Paypal-Transmission-Id": {"transmission-1"}, "Paypal-Transmission-Sig": {"signature"}, "Paypal-Transmission-Time": {time.Now().UTC().Format(time.RFC3339)},
	}
	verified, err := client.VerifyWebhook(t.Context(), headers, json.RawMessage(`{"id":"WH-EVENT"}`))
	if err != nil || !verified {
		t.Fatalf("verified=%v err=%v", verified, err)
	}
	headers.Set("PayPal-Transmission-Time", time.Now().UTC().Add(-6*time.Minute).Format(time.RFC3339))
	verified, err = client.VerifyWebhook(t.Context(), headers, json.RawMessage(`{"id":"WH-EVENT"}`))
	if err != nil || verified {
		t.Fatalf("stale transmission verified=%v err=%v", verified, err)
	}
}

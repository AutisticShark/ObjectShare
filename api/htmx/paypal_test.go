package htmx

import (
	"context"
	"encoding/json"
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
	verified    bool
	details     paypalSubscription
	detailCalls int
}

func (stub *paypalGatewayStub) Checkout(context.Context, billingCheckoutInput) (string, error) {
	return "https://www.sandbox.paypal.com/approve", nil
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
		case "/v1/billing/subscriptions":
			checkoutCalls++
			if request.Header.Get("Authorization") != "Bearer token" || request.Header.Get("PayPal-Request-Id") == "" {
				t.Errorf("missing authenticated or idempotent request headers")
			}
			var body map[string]any
			if json.NewDecoder(request.Body).Decode(&body) != nil || body["plan_id"] != "P-ABCDEFGHIJKLMNOPQRSTUVWX" || body["custom_id"] != "11111111-1111-4111-8111-111111111111" {
				t.Errorf("unexpected checkout body: %#v", body)
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"links":[{"rel":"approve","href":"https://www.sandbox.paypal.com/webapps/billing/subscriptions?ba_token=BA-1"}]}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client := &paypalClient{settings: config.PayPalBillingConfig{Environment: "sandbox", ClientID: "client", ClientSecret: "secret"}, apiBase: server.URL, webBase: "https://www.sandbox.paypal.com", client: server.Client()}
	input := billingCheckoutInput{GatewayPlanID: "P-ABCDEFGHIJKLMNOPQRSTUVWX", UserID: "11111111-1111-4111-8111-111111111111", Email: "user@example.com", SuccessURL: "https://share.example.com/account", CancelURL: "https://share.example.com/plans"}
	for range 2 {
		location, err := client.Checkout(t.Context(), input)
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

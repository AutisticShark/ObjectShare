package htmx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/go-chi/chi/v5"
)

func TestBillingGatewayModulesOwnTopUpConfiguration(t *testing.T) {
	settings := &config.BillingConfig{
		Stripe: config.StripeBillingConfig{Enabled: true, SecretKey: "sk_test"},
		PayPal: config.PayPalBillingConfig{Enabled: true, Environment: "sandbox", ClientID: "client", ClientSecret: "secret", WebhookID: "hook"},
	}
	gateways := configuredBillingGateways(settings)
	if _, ok := gateways[db.BillingGatewayStripe].(*stripeClient); !ok {
		t.Fatalf("Stripe gateway type = %T", gateways[db.BillingGatewayStripe])
	}
	if _, ok := gateways[db.BillingGatewayPayPal].(*paypalClient); !ok {
		t.Fatalf("PayPal gateway type = %T", gateways[db.BillingGatewayPayPal])
	}

	options := billingGatewayOptions()
	if len(options) != 2 || options[0] != (billingGatewayOption{Key: db.BillingGatewayStripe, Label: "Stripe"}) || options[1] != (billingGatewayOption{Key: db.BillingGatewayPayPal, Label: "PayPal"}) {
		t.Fatalf("gateway options = %#v", options)
	}
}

func TestBillingWebhookDispatchesByRegisteredGateway(t *testing.T) {
	repository := &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}}
	handler := newTestHandler(t, repository, &memoryStorage{objects: make(map[string][]byte)})
	handler.billingGateways = map[string]billingGateway{
		db.BillingGatewayStripe: newStripeClient(config.StripeBillingConfig{WebhookSecret: "whsec_test"}),
	}
	router := chi.NewRouter()
	router.Post("/{gateway}", handler.BillingWebhook)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/stripe", nil))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("registered gateway status = %d, want %d", response.Code, http.StatusBadRequest)
	}

	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/unknown", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown gateway status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestGatewayErrorsCarryProviderRequestIdentifiers(t *testing.T) {
	stripe := &http.Response{StatusCode: http.StatusBadRequest, Header: http.Header{"Request-Id": {"req_abc123"}}}
	err := stripeAPIError(stripe, []byte(`{"error":{"type":"invalid_request_error","code":"amount_too_small","message":"Amount must be at least $0.50"}}`))
	for _, want := range []string{"HTTP 400", "req_abc123", "invalid_request_error/amount_too_small", "Amount must be at least"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Stripe error %q lacks %q", err, want)
		}
	}

	paypal := &http.Response{StatusCode: http.StatusUnprocessableEntity, Header: http.Header{"Paypal-Debug-Id": {"dbg-9f8e7d"}}}
	err = paypalAPIError(paypal, []byte(`{"name":"UNPROCESSABLE_ENTITY","message":"The requested action could not be performed"}`))
	for _, want := range []string{"HTTP 422", "dbg-9f8e7d", "UNPROCESSABLE_ENTITY", "could not be performed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("PayPal error %q lacks %q", err, want)
		}
	}
	// The debug id may only be in the body, and hostile bodies are bounded and stripped of control characters.
	noHeader := &http.Response{StatusCode: http.StatusBadGateway, Header: http.Header{}}
	hostile, _ := json.Marshal(map[string]string{"debug_id": "body-debug", "message": strings.Repeat("x\r\n", 500)})
	err = paypalAPIError(noHeader, hostile)
	if !strings.Contains(err.Error(), "body-debug") || len(err.Error()) > 400 || strings.ContainsAny(err.Error(), "\r\n") {
		t.Fatalf("unbounded or unsafe error text: %q", err)
	}
	if plain := stripeAPIError(&http.Response{StatusCode: 503, Header: http.Header{}}, []byte("<html>")); plain.Error() != "Stripe returned HTTP 503" {
		t.Fatalf("non-JSON bodies must still yield a status error, got %q", plain)
	}
}

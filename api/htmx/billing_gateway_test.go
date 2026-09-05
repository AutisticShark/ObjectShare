package htmx

import (
	"net/http"
	"net/http/httptest"
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

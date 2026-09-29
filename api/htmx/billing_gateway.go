package htmx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/go-chi/chi/v5"
)

type billingGateway interface {
	TopUp(context.Context, billingTopUpInput) (billingTopUpResult, error)
	Portal(context.Context, *db.Subscription, string) (string, error)
}

type billingTopUpInput struct {
	TopUpID, UserID, Email, Currency, SuccessURL, CancelURL, Description string
	Credits, AmountMinor                                                 int64
}

type billingTopUpResult struct {
	Location, GatewayReference string
}

type billingGatewayModule interface {
	Key() string
	Label() string
	Order() int
	Configure(*config.BillingConfig) billingGateway
	HandleWebhook(*Handler, http.ResponseWriter, *http.Request)
}

type billingGatewayOption struct {
	Key   string
	Label string
}

var billingGatewayModules []billingGatewayModule

func registerBillingGatewayModule(module billingGatewayModule) {
	for _, registered := range billingGatewayModules {
		if registered.Key() == module.Key() {
			panic("duplicate billing gateway module: " + module.Key())
		}
	}
	billingGatewayModules = append(billingGatewayModules, module)
}

func configuredBillingGateways(settings *config.BillingConfig) map[string]billingGateway {
	gateways := make(map[string]billingGateway)
	for _, module := range billingGatewayModules {
		if gateway := module.Configure(settings); gateway != nil {
			gateways[module.Key()] = gateway
		}
	}
	return gateways
}

func billingGatewayModuleFor(key string) billingGatewayModule {
	for _, module := range billingGatewayModules {
		if module.Key() == key {
			return module
		}
	}
	return nil
}

func billingGatewayLabel(gateway string) string {
	if module := billingGatewayModuleFor(gateway); module != nil {
		return module.Label()
	}
	return "Unknown gateway"
}

func billingGatewayOptions() []billingGatewayOption {
	modules := append([]billingGatewayModule(nil), billingGatewayModules...)
	sort.Slice(modules, func(left, right int) bool {
		if modules[left].Order() == modules[right].Order() {
			return modules[left].Key() < modules[right].Key()
		}
		return modules[left].Order() < modules[right].Order()
	})
	options := make([]billingGatewayOption, 0, len(modules))
	for _, module := range modules {
		options = append(options, billingGatewayOption{Key: module.Key(), Label: module.Label()})
	}
	return options
}

func (handler *Handler) BillingWebhook(writer http.ResponseWriter, request *http.Request) {
	key := chi.URLParam(request, "gateway")
	module := billingGatewayModuleFor(key)
	if module == nil || handler.billingGateways[key] == nil || handler.billing == nil {
		http.NotFound(writer, request)
		return
	}
	module.HandleWebhook(handler, writer, request)
}

// errorDetailLimit bounds provider text copied into an error so a hostile or
// broken response cannot flood the logs.
const errorDetailLimit = 200

func limitedText(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return ' '
		}
		return r
	}, value)
	if len(value) > errorDetailLimit {
		return value[:errorDetailLimit] + "..."
	}
	return value
}

// stripeAPIError turns a failed Stripe API response into an error that carries
// what support needs (HTTP status, error type and code, message and the
// Request-Id) instead of a bare status code. The Authorization header and the
// request body are never included.
func stripeAPIError(response *http.Response, body []byte) error {
	var payload struct {
		Error struct {
			Type    string `json:"type"`
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &payload)
	parts := []string{fmt.Sprintf("Stripe returned HTTP %d", response.StatusCode)}
	if id := response.Header.Get("Request-Id"); id != "" {
		parts = append(parts, "request "+limitedText(id))
	}
	if payload.Error.Type != "" || payload.Error.Code != "" {
		parts = append(parts, "error "+limitedText(payload.Error.Type+"/"+payload.Error.Code))
	}
	if payload.Error.Message != "" {
		parts = append(parts, limitedText(payload.Error.Message))
	}
	return errors.New(strings.Join(parts, "; "))
}

// paypalAPIError is the PayPal equivalent, including the PayPal-Debug-Id that
// PayPal support asks for.
func paypalAPIError(response *http.Response, body []byte) error {
	var payload struct {
		Name    string `json:"name"`
		Message string `json:"message"`
		DebugID string `json:"debug_id"`
	}
	_ = json.Unmarshal(body, &payload)
	debugID := response.Header.Get("PayPal-Debug-Id")
	if debugID == "" {
		debugID = payload.DebugID
	}
	parts := []string{fmt.Sprintf("PayPal returned HTTP %d", response.StatusCode)}
	if debugID != "" {
		parts = append(parts, "debug id "+limitedText(debugID))
	}
	if payload.Name != "" {
		parts = append(parts, limitedText(payload.Name))
	}
	if payload.Message != "" {
		parts = append(parts, limitedText(payload.Message))
	}
	return errors.New(strings.Join(parts, "; "))
}

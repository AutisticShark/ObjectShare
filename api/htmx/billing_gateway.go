package htmx

import (
	"context"
	"net/http"
	"sort"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/go-chi/chi/v5"
)

type billingGateway interface {
	Checkout(context.Context, billingCheckoutInput) (string, error)
	TopUp(context.Context, billingTopUpInput) (billingTopUpResult, error)
	Portal(context.Context, *db.Subscription, string) (string, error)
}

type billingCheckoutInput struct {
	GatewayPlanID string
	UserID        string
	Email         string
	CustomerID    string
	SuccessURL    string
	CancelURL     string
}

type billingTopUpInput struct {
	TopUpID, UserID, Email, Currency, SuccessURL, CancelURL string
	Credits, AmountMinor                                    int64
}

type billingTopUpResult struct {
	Location, GatewayReference string
}

type billingGatewayModule interface {
	Key() string
	Label() string
	Order() int
	ValidPlanID(string) bool
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

func validGatewayPlanID(gateway, planID string) bool {
	module := billingGatewayModuleFor(gateway)
	return module != nil && module.ValidPlanID(planID)
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

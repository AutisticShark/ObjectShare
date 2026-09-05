package htmx

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/google/uuid"
)

const stripeAPIBase = "https://api.stripe.com/v1"

type stripeGatewayModule struct{}

func init() { registerBillingGatewayModule(stripeGatewayModule{}) }

func (stripeGatewayModule) Key() string   { return db.BillingGatewayStripe }
func (stripeGatewayModule) Label() string { return "Stripe" }
func (stripeGatewayModule) Order() int    { return 100 }
func (stripeGatewayModule) Configure(settings *config.BillingConfig) billingGateway {
	if settings == nil || !settings.Stripe.Enabled {
		return nil
	}
	return newStripeClient(settings.Stripe)
}
func (stripeGatewayModule) HandleWebhook(handler *Handler, writer http.ResponseWriter, request *http.Request) {
	handler.StripeWebhook(writer, request)
}

type stripeClient struct {
	secret        string
	webhookSecret string
	apiBase       string
	client        *http.Client
}

type stripeBillingGateway interface {
	billingGateway
	WebhookSigningSecret() string
}

func newStripeClient(settings config.StripeBillingConfig) billingGateway {
	return &stripeClient{secret: settings.SecretKey, webhookSecret: settings.WebhookSecret, apiBase: stripeAPIBase, client: &http.Client{Timeout: 15 * time.Second}}
}

func (client *stripeClient) WebhookSigningSecret() string { return client.webhookSecret }

func (client *stripeClient) postForm(ctx context.Context, endpoint string, values url.Values, idempotencyKey string) (string, error) {
	apiBase := client.apiBase
	if apiBase == "" {
		apiBase = stripeAPIBase
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", "Bearer "+client.secret)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Stripe-Version", "2024-06-20")
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	response, err := client.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err != nil {
		return "", err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("Stripe returned HTTP %d", response.StatusCode)
	}
	var result struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(body, &result); err != nil || result.URL == "" {
		return "", errors.New("Stripe returned an invalid session")
	}
	parsed, err := url.Parse(result.URL)
	if err != nil || parsed.Scheme != "https" || !strings.HasSuffix(strings.ToLower(parsed.Hostname()), ".stripe.com") {
		return "", errors.New("Stripe returned an unsafe session URL")
	}
	return result.URL, nil
}

func (client *stripeClient) TopUp(ctx context.Context, input billingTopUpInput) (billingTopUpResult, error) {
	values := url.Values{
		"mode": {"payment"}, "line_items[0][price_data][currency]": {strings.ToLower(input.Currency)},
		"line_items[0][price_data][unit_amount]":               {strconv.FormatInt(input.AmountMinor, 10)},
		"line_items[0][price_data][product_data][name]":        {"ObjectShare account credit"},
		"line_items[0][price_data][product_data][description]": {fmt.Sprintf("%d account credits", input.Credits)},
		"line_items[0][quantity]":                              {"1"}, "success_url": {input.SuccessURL}, "cancel_url": {input.CancelURL},
		"client_reference_id": {input.UserID}, "customer_email": {input.Email},
		"metadata[purpose]": {"credit_topup"}, "metadata[topup_id]": {input.TopUpID},
		"payment_intent_data[metadata][purpose]": {"credit_topup"}, "payment_intent_data[metadata][topup_id]": {input.TopUpID},
	}
	location, err := client.postForm(ctx, "/checkout/sessions", values, "objectshare-topup-"+input.TopUpID)
	return billingTopUpResult{Location: location}, err
}

func (client *stripeClient) Portal(ctx context.Context, subscription *db.Subscription, returnURL string) (string, error) {
	return client.postForm(ctx, "/billing_portal/sessions", url.Values{"customer": {subscription.CustomerID}, "return_url": {returnURL}}, "")
}

type stripeEvent struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Created int64  `json:"created"`
	Data    struct {
		Object json.RawMessage `json:"object"`
	} `json:"data"`
}

type stripeSubscription struct {
	ID                string            `json:"id"`
	Customer          string            `json:"customer"`
	Status            string            `json:"status"`
	CurrentPeriodEnd  int64             `json:"current_period_end"`
	CancelAtPeriodEnd bool              `json:"cancel_at_period_end"`
	Metadata          map[string]string `json:"metadata"`
	Items             struct {
		Data []struct {
			CurrentPeriodEnd int64 `json:"current_period_end"`
			Price            struct {
				ID string `json:"id"`
			} `json:"price"`
		} `json:"data"`
	} `json:"items"`
}

type stripeCheckoutSession struct {
	ID            string            `json:"id"`
	Mode          string            `json:"mode"`
	PaymentStatus string            `json:"payment_status"`
	PaymentIntent string            `json:"payment_intent"`
	AmountTotal   int64             `json:"amount_total"`
	Currency      string            `json:"currency"`
	Metadata      map[string]string `json:"metadata"`
}

func (handler *Handler) StripeWebhook(writer http.ResponseWriter, request *http.Request) {
	gateway, ok := handler.billingGateways[db.BillingGatewayStripe].(stripeBillingGateway)
	if !ok || handler.billing == nil {
		http.NotFound(writer, request)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 1024*1024)
	payload, err := io.ReadAll(request.Body)
	if err != nil {
		http.Error(writer, "Invalid webhook body.", http.StatusBadRequest)
		return
	}
	if !verifyStripeSignature(payload, request.Header.Get("Stripe-Signature"), gateway.WebhookSigningSecret(), time.Now().UTC()) {
		http.Error(writer, "Invalid Stripe signature.", http.StatusBadRequest)
		return
	}
	var event stripeEvent
	if err := json.Unmarshal(payload, &event); err != nil || event.ID == "" || event.Created <= 0 {
		http.Error(writer, "Invalid Stripe event.", http.StatusBadRequest)
		return
	}
	if event.Type == "checkout.session.completed" || event.Type == "checkout.session.async_payment_succeeded" {
		var session stripeCheckoutSession
		if err := json.Unmarshal(event.Data.Object, &session); err != nil || session.ID == "" {
			http.Error(writer, "Invalid Stripe Checkout event.", http.StatusBadRequest)
			return
		}
		if session.Metadata["purpose"] != "credit_topup" {
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		if session.PaymentStatus == "unpaid" && event.Type == "checkout.session.completed" {
			// Delayed payment methods settle in async_payment_succeeded.
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		if session.Mode != "payment" || session.PaymentStatus != "paid" || session.PaymentIntent == "" || session.AmountTotal <= 0 {
			http.Error(writer, "Stripe top-up is not paid.", http.StatusUnprocessableEntity)
			return
		}
		topUpID := session.Metadata["topup_id"]
		if _, err := uuid.Parse(topUpID); err != nil {
			http.Error(writer, "Invalid Stripe top-up metadata.", http.StatusUnprocessableEntity)
			return
		}
		_, err = handler.billing.ApplyCreditTopUp(request.Context(), db.CreditPayment{TopUpID: topUpID, Gateway: db.BillingGatewayStripe,
			GatewayPaymentID: session.PaymentIntent, Currency: session.Currency, AmountMinor: session.AmountTotal}, time.Now().UTC())
		if errors.Is(err, db.ErrNotFound) || errors.Is(err, db.ErrInvalidCredit) || errors.Is(err, db.ErrConflict) {
			http.Error(writer, "Stripe top-up did not match a pending account payment.", http.StatusUnprocessableEntity)
			return
		}
		if err != nil {
			handler.internalError(writer, request, "apply Stripe credit top-up", err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	if event.Type != "customer.subscription.created" && event.Type != "customer.subscription.updated" && event.Type != "customer.subscription.deleted" {
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	var subscription stripeSubscription
	if err := json.Unmarshal(event.Data.Object, &subscription); err != nil || subscription.ID == "" || subscription.Customer == "" || len(subscription.Items.Data) != 1 {
		http.Error(writer, "Invalid Stripe subscription event.", http.StatusBadRequest)
		return
	}
	priceID := subscription.Items.Data[0].Price.ID
	plan, err := handler.billing.PlanByGatewayID(request.Context(), db.BillingGatewayStripe, priceID)
	if errors.Is(err, db.ErrNotFound) {
		http.Error(writer, "Stripe Price is not mapped to a plan.", http.StatusUnprocessableEntity)
		return
	}
	if err != nil {
		handler.internalError(writer, request, "map Stripe Price", err)
		return
	}
	userID := subscription.Metadata["user_id"]
	if _, err := uuid.Parse(userID); err != nil {
		http.Error(writer, "Invalid subscription user metadata.", http.StatusUnprocessableEntity)
		return
	}
	periodEnd := subscription.CurrentPeriodEnd
	if periodEnd == 0 {
		periodEnd = subscription.Items.Data[0].CurrentPeriodEnd
	}
	if periodEnd == 0 {
		periodEnd = event.Created
	}
	_, err = handler.billing.ApplySubscription(request.Context(), db.SubscriptionUpdate{Gateway: db.BillingGatewayStripe, EventID: event.ID,
		EventCreated: event.Created, UserID: userID, PlanID: plan.ID, CustomerID: subscription.Customer,
		SubscriptionID: subscription.ID, Status: subscription.Status, CurrentPeriodEnd: time.Unix(periodEnd, 0).UTC(), CancelAtPeriodEnd: subscription.CancelAtPeriodEnd})
	if errors.Is(err, db.ErrNotFound) {
		http.Error(writer, "Subscription account was not found.", http.StatusUnprocessableEntity)
		return
	}
	if err != nil {
		handler.internalError(writer, request, "apply Stripe subscription", err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func verifyStripeSignature(payload []byte, header, secret string, now time.Time) bool {
	var timestamp int64
	var signatures []string
	for _, field := range strings.Split(header, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok {
			continue
		}
		if key == "t" {
			timestamp, _ = strconv.ParseInt(value, 10, 64)
		}
		if key == "v1" {
			signatures = append(signatures, value)
		}
	}
	if timestamp <= 0 || len(signatures) == 0 || now.Sub(time.Unix(timestamp, 0)) > 5*time.Minute || time.Unix(timestamp, 0).Sub(now) > 5*time.Minute {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = fmt.Fprintf(mac, "%d.", timestamp)
	_, _ = mac.Write(payload)
	expected := mac.Sum(nil)
	for _, signature := range signatures {
		provided, err := hex.DecodeString(signature)
		if err == nil && hmac.Equal(expected, provided) {
			return true
		}
	}
	return false
}

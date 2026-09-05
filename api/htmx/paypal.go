package htmx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/google/uuid"
)

type paypalGatewayModule struct{}

func init() { registerBillingGatewayModule(paypalGatewayModule{}) }

func (paypalGatewayModule) Key() string   { return db.BillingGatewayPayPal }
func (paypalGatewayModule) Label() string { return "PayPal" }
func (paypalGatewayModule) Order() int    { return 200 }
func (paypalGatewayModule) Configure(settings *config.BillingConfig) billingGateway {
	if settings == nil || !settings.PayPal.Enabled {
		return nil
	}
	return newPayPalClient(settings.PayPal)
}
func (paypalGatewayModule) HandleWebhook(handler *Handler, writer http.ResponseWriter, request *http.Request) {
	handler.PayPalWebhook(writer, request)
}

type paypalBillingGateway interface {
	billingGateway
	VerifyWebhook(context.Context, http.Header, json.RawMessage) (bool, error)
	SubscriptionDetails(context.Context, string) (paypalSubscription, error)
	CaptureTopUp(context.Context, string) (paypalCapture, error)
}

type paypalClient struct {
	settings config.PayPalBillingConfig
	apiBase  string
	webBase  string
	client   *http.Client
	tokenMu  sync.Mutex
	token    string
	expires  time.Time
}

type paypalSubscription struct {
	ID               string       `json:"id"`
	PlanID           string       `json:"plan_id"`
	CustomID         string       `json:"custom_id"`
	Status           string       `json:"status"`
	StatusUpdateTime string       `json:"status_update_time"`
	Amount           paypalAmount `json:"amount"`
	Subscriber       struct {
		PayerID string `json:"payer_id"`
	} `json:"subscriber"`
	BillingInfo struct {
		NextBillingTime string `json:"next_billing_time"`
	} `json:"billing_info"`
}

type paypalAmount struct {
	Currency string `json:"currency_code"`
	Value    string `json:"value"`
}

type paypalCapture struct {
	ID       string       `json:"id"`
	CustomID string       `json:"custom_id"`
	Status   string       `json:"status"`
	Amount   paypalAmount `json:"amount"`
}

func newPayPalClient(settings config.PayPalBillingConfig) billingGateway {
	apiBase, webBase := "https://api-m.paypal.com", "https://www.paypal.com"
	if settings.Environment == "sandbox" {
		apiBase, webBase = "https://api-m.sandbox.paypal.com", "https://www.sandbox.paypal.com"
	}
	return &paypalClient{settings: settings, apiBase: apiBase, webBase: webBase, client: &http.Client{Timeout: 15 * time.Second}}
}

func (client *paypalClient) TopUp(ctx context.Context, input billingTopUpInput) (billingTopUpResult, error) {
	body := struct {
		Intent        string `json:"intent"`
		PurchaseUnits []struct {
			ReferenceID string       `json:"reference_id"`
			CustomID    string       `json:"custom_id"`
			Description string       `json:"description"`
			Amount      paypalAmount `json:"amount"`
		} `json:"purchase_units"`
		PaymentSource struct {
			PayPal struct {
				ExperienceContext struct {
					ShippingPreference string `json:"shipping_preference"`
					UserAction         string `json:"user_action"`
					ReturnURL          string `json:"return_url"`
					CancelURL          string `json:"cancel_url"`
				} `json:"experience_context"`
			} `json:"paypal"`
		} `json:"payment_source"`
	}{Intent: "CAPTURE", PurchaseUnits: make([]struct {
		ReferenceID string       `json:"reference_id"`
		CustomID    string       `json:"custom_id"`
		Description string       `json:"description"`
		Amount      paypalAmount `json:"amount"`
	}, 1)}
	body.PurchaseUnits[0].ReferenceID = input.TopUpID
	body.PurchaseUnits[0].CustomID = input.TopUpID
	body.PurchaseUnits[0].Description = fmt.Sprintf("%d ObjectShare account credits", input.Credits)
	body.PurchaseUnits[0].Amount = paypalAmount{Currency: input.Currency, Value: formatMinorAmount(input.AmountMinor)}
	body.PaymentSource.PayPal.ExperienceContext.ShippingPreference = "NO_SHIPPING"
	body.PaymentSource.PayPal.ExperienceContext.UserAction = "PAY_NOW"
	body.PaymentSource.PayPal.ExperienceContext.ReturnURL = input.SuccessURL
	body.PaymentSource.PayPal.ExperienceContext.CancelURL = input.CancelURL
	var response struct {
		ID    string `json:"id"`
		Links []struct {
			Href string `json:"href"`
			Rel  string `json:"rel"`
		} `json:"links"`
	}
	if err := client.requestJSON(ctx, http.MethodPost, "/v2/checkout/orders", body, &response, map[string]string{"PayPal-Request-Id": input.TopUpID}); err != nil {
		return billingTopUpResult{}, err
	}
	if response.ID == "" {
		return billingTopUpResult{}, errors.New("PayPal returned an invalid order")
	}
	for _, link := range response.Links {
		if (link.Rel == "payer-action" || link.Rel == "approve") && client.safeBrowserURL(link.Href) {
			return billingTopUpResult{Location: link.Href, GatewayReference: response.ID}, nil
		}
	}
	return billingTopUpResult{}, errors.New("PayPal returned no safe approval URL")
}

func (client *paypalClient) CaptureTopUp(ctx context.Context, orderID string) (paypalCapture, error) {
	var order struct {
		ID            string `json:"id"`
		Status        string `json:"status"`
		PurchaseUnits []struct {
			Payments struct {
				Captures []paypalCapture `json:"captures"`
			} `json:"payments"`
		} `json:"purchase_units"`
	}
	endpoint := "/v2/checkout/orders/" + url.PathEscape(orderID)
	if err := client.requestJSON(ctx, http.MethodPost, endpoint+"/capture", struct{}{}, &order, map[string]string{"PayPal-Request-Id": "capture-" + orderID, "Prefer": "return=representation"}); err != nil {
		// A previous capture may have succeeded before the response was lost.
		// Only an authenticated, completed order is accepted by the checks below.
		if readErr := client.requestJSON(ctx, http.MethodGet, endpoint, nil, &order, nil); readErr != nil {
			return paypalCapture{}, err
		}
	}
	if order.ID != orderID || order.Status != "COMPLETED" || len(order.PurchaseUnits) != 1 || len(order.PurchaseUnits[0].Payments.Captures) != 1 {
		return paypalCapture{}, errors.New("PayPal returned an incomplete capture")
	}
	capture := order.PurchaseUnits[0].Payments.Captures[0]
	if capture.ID == "" || capture.Status != "COMPLETED" {
		return paypalCapture{}, errors.New("PayPal payment was not completed")
	}
	return capture, nil
}

func (client *paypalClient) Portal(_ context.Context, _ *db.Subscription, _ string) (string, error) {
	return client.webBase + "/myaccount/autopay/connect/", nil
}

func (client *paypalClient) safeBrowserURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil {
		return false
	}
	expected, _ := url.Parse(client.webBase)
	return strings.EqualFold(parsed.Host, expected.Host)
}

func (client *paypalClient) VerifyWebhook(ctx context.Context, headers http.Header, event json.RawMessage) (bool, error) {
	values := map[string]string{
		"auth_algo":         headers.Get("PayPal-Auth-Algo"),
		"cert_url":          headers.Get("PayPal-Cert-Url"),
		"transmission_id":   headers.Get("PayPal-Transmission-Id"),
		"transmission_sig":  headers.Get("PayPal-Transmission-Sig"),
		"transmission_time": headers.Get("PayPal-Transmission-Time"),
		"webhook_id":        client.settings.WebhookID,
	}
	limits := map[string]int{"auth_algo": 100, "cert_url": 500, "transmission_id": 50, "transmission_sig": 500, "transmission_time": 100, "webhook_id": 50}
	for key, value := range values {
		if value == "" || len(value) > limits[key] {
			return false, nil
		}
	}
	transmittedAt, err := time.Parse(time.RFC3339, values["transmission_time"])
	if err != nil || time.Since(transmittedAt) > 5*time.Minute || time.Until(transmittedAt) > 5*time.Minute {
		return false, nil
	}
	body := struct {
		AuthAlgo         string          `json:"auth_algo"`
		CertURL          string          `json:"cert_url"`
		TransmissionID   string          `json:"transmission_id"`
		TransmissionSig  string          `json:"transmission_sig"`
		TransmissionTime string          `json:"transmission_time"`
		WebhookID        string          `json:"webhook_id"`
		WebhookEvent     json.RawMessage `json:"webhook_event"`
	}{values["auth_algo"], values["cert_url"], values["transmission_id"], values["transmission_sig"], values["transmission_time"], values["webhook_id"], event}
	var response struct {
		Status string `json:"verification_status"`
	}
	if err := client.requestJSON(ctx, http.MethodPost, "/v1/notifications/verify-webhook-signature", body, &response, nil); err != nil {
		return false, err
	}
	return response.Status == "SUCCESS", nil
}

func (client *paypalClient) SubscriptionDetails(ctx context.Context, subscriptionID string) (paypalSubscription, error) {
	var subscription paypalSubscription
	err := client.requestJSON(ctx, http.MethodGet, "/v1/billing/subscriptions/"+url.PathEscape(subscriptionID), nil, &subscription, nil)
	return subscription, err
}

func (client *paypalClient) requestJSON(ctx context.Context, method, endpoint string, body, result any, headers map[string]string) error {
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		token, err := client.accessToken(ctx)
		if err != nil {
			return err
		}
		request, err := http.NewRequestWithContext(ctx, method, client.apiBase+endpoint, bytes.NewReader(encoded))
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Accept", "application/json")
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		response, err := client.client.Do(request)
		if err != nil {
			return err
		}
		responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, 128*1024))
		_ = response.Body.Close()
		if readErr != nil {
			return readErr
		}
		if response.StatusCode == http.StatusUnauthorized && attempt == 0 {
			client.invalidateToken(token)
			continue
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return fmt.Errorf("PayPal returned HTTP %d", response.StatusCode)
		}
		if result != nil && (len(responseBody) == 0 || json.Unmarshal(responseBody, result) != nil) {
			return errors.New("PayPal returned an invalid response")
		}
		return nil
	}
	return errors.New("PayPal rejected the refreshed access token")
}

func (client *paypalClient) invalidateToken(token string) {
	client.tokenMu.Lock()
	defer client.tokenMu.Unlock()
	if client.token == token {
		client.token, client.expires = "", time.Time{}
	}
}

func (client *paypalClient) accessToken(ctx context.Context) (string, error) {
	client.tokenMu.Lock()
	defer client.tokenMu.Unlock()
	if client.token != "" && time.Now().UTC().Add(time.Minute).Before(client.expires) {
		return client.token, nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.apiBase+"/v1/oauth2/token", strings.NewReader("grant_type=client_credentials"))
	if err != nil {
		return "", err
	}
	request.SetBasicAuth(client.settings.ClientID, client.settings.ClientSecret)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err != nil {
		return "", err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("PayPal OAuth returned HTTP %d", response.StatusCode)
	}
	var token struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if json.Unmarshal(responseBody, &token) != nil || token.AccessToken == "" || token.ExpiresIn <= 0 {
		return "", errors.New("PayPal OAuth returned an invalid access token")
	}
	client.token = token.AccessToken
	client.expires = time.Now().UTC().Add(time.Duration(token.ExpiresIn) * time.Second)
	return client.token, nil
}

type paypalEvent struct {
	ID         string             `json:"id"`
	EventType  string             `json:"event_type"`
	CreateTime string             `json:"create_time"`
	Resource   paypalSubscription `json:"resource"`
}

func (handler *Handler) PayPalWebhook(writer http.ResponseWriter, request *http.Request) {
	gateway, ok := handler.billingGateways[db.BillingGatewayPayPal].(paypalBillingGateway)
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
	var event paypalEvent
	if err := json.Unmarshal(payload, &event); err != nil || event.ID == "" || event.EventType == "" || event.Resource.ID == "" {
		http.Error(writer, "Invalid PayPal event.", http.StatusBadRequest)
		return
	}
	created, err := time.Parse(time.RFC3339, event.CreateTime)
	if err != nil {
		http.Error(writer, "Invalid PayPal event time.", http.StatusBadRequest)
		return
	}
	verified, err := gateway.VerifyWebhook(request.Context(), request.Header, json.RawMessage(payload))
	if err != nil {
		handler.internalError(writer, request, "verify PayPal webhook", err)
		return
	}
	if !verified {
		http.Error(writer, "Invalid PayPal signature.", http.StatusBadRequest)
		return
	}
	if event.EventType == "BILLING.SUBSCRIPTION.CREATED" {
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	if event.EventType == "PAYMENT.CAPTURE.COMPLETED" {
		amountMinor, amountErr := parseMinorAmount(event.Resource.Amount.Value)
		if amountErr != nil || event.Resource.CustomID == "" || event.Resource.Status != "COMPLETED" {
			http.Error(writer, "Invalid PayPal top-up capture.", http.StatusBadRequest)
			return
		}
		if _, parseErr := uuid.Parse(event.Resource.CustomID); parseErr != nil {
			http.Error(writer, "Invalid PayPal top-up metadata.", http.StatusUnprocessableEntity)
			return
		}
		_, applyErr := handler.billing.ApplyCreditTopUp(request.Context(), db.CreditPayment{TopUpID: event.Resource.CustomID,
			Gateway: db.BillingGatewayPayPal, GatewayPaymentID: event.Resource.ID, Currency: event.Resource.Amount.Currency, AmountMinor: amountMinor}, time.Now().UTC())
		if errors.Is(applyErr, db.ErrNotFound) || errors.Is(applyErr, db.ErrInvalidCredit) || errors.Is(applyErr, db.ErrConflict) {
			http.Error(writer, "PayPal top-up did not match a pending account payment.", http.StatusUnprocessableEntity)
			return
		}
		if applyErr != nil {
			handler.internalError(writer, request, "apply PayPal credit top-up", applyErr)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	if !paypalSubscriptionEvent(event.EventType) {
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	detailsLoaded := false
	if event.EventType == "BILLING.SUBSCRIPTION.PAYMENT.FAILED" || event.Resource.PlanID == "" || event.Resource.CustomID == "" || event.Resource.Status == "" {
		details, detailErr := gateway.SubscriptionDetails(request.Context(), event.Resource.ID)
		if detailErr != nil {
			handler.internalError(writer, request, "load PayPal subscription details", detailErr)
			return
		}
		event.Resource = details
		detailsLoaded = true
	}
	plan, err := handler.billing.PlanByGatewayID(request.Context(), db.BillingGatewayPayPal, event.Resource.PlanID)
	if errors.Is(err, db.ErrNotFound) {
		http.Error(writer, "PayPal plan is not mapped to a plan.", http.StatusUnprocessableEntity)
		return
	}
	if err != nil {
		handler.internalError(writer, request, "map PayPal plan", err)
		return
	}
	userID := event.Resource.CustomID
	if _, err := uuid.Parse(userID); err != nil {
		http.Error(writer, "Invalid subscription user metadata.", http.StatusUnprocessableEntity)
		return
	}
	status := normalizePayPalStatus(event.Resource.Status)
	periodEnd, periodErr := time.Parse(time.RFC3339, event.Resource.BillingInfo.NextBillingTime)
	if status == "active" && periodErr != nil && !detailsLoaded {
		details, detailErr := gateway.SubscriptionDetails(request.Context(), event.Resource.ID)
		if detailErr != nil {
			handler.internalError(writer, request, "load PayPal subscription", detailErr)
			return
		}
		periodEnd, periodErr = time.Parse(time.RFC3339, details.BillingInfo.NextBillingTime)
	}
	if periodErr != nil {
		if status == "active" {
			http.Error(writer, "PayPal subscription has no next billing time.", http.StatusUnprocessableEntity)
			return
		}
		periodEnd = created
	}
	_, err = handler.billing.ApplySubscription(request.Context(), db.SubscriptionUpdate{
		Gateway: db.BillingGatewayPayPal, EventID: event.ID, EventCreated: created.Unix(), UserID: userID,
		PlanID: plan.ID, CustomerID: event.Resource.Subscriber.PayerID, SubscriptionID: event.Resource.ID,
		Status: status, CurrentPeriodEnd: periodEnd.UTC(),
	})
	if errors.Is(err, db.ErrNotFound) {
		http.Error(writer, "Subscription account was not found.", http.StatusUnprocessableEntity)
		return
	}
	if err != nil {
		handler.internalError(writer, request, "apply PayPal subscription", err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func paypalSubscriptionEvent(eventType string) bool {
	switch eventType {
	case "BILLING.SUBSCRIPTION.ACTIVATED", "BILLING.SUBSCRIPTION.UPDATED", "BILLING.SUBSCRIPTION.SUSPENDED",
		"BILLING.SUBSCRIPTION.CANCELLED", "BILLING.SUBSCRIPTION.EXPIRED", "BILLING.SUBSCRIPTION.PAYMENT.FAILED":
		return true
	default:
		return false
	}
}

func normalizePayPalStatus(status string) string {
	switch strings.ToUpper(status) {
	case "ACTIVE":
		return "active"
	case "CANCELLED":
		return "canceled"
	case "EXPIRED":
		return "expired"
	case "SUSPENDED":
		return "suspended"
	case "APPROVAL_PENDING", "APPROVED":
		return "incomplete"
	default:
		return strings.ToLower(status)
	}
}

func formatMinorAmount(amount int64) string {
	return fmt.Sprintf("%d.%02d", amount/100, amount%100)
}

func parseMinorAmount(value string) (int64, error) {
	whole, fraction, ok := strings.Cut(value, ".")
	if !ok || len(fraction) != 2 || whole == "" {
		return 0, errors.New("amount must have two decimal places")
	}
	for _, digit := range whole + fraction {
		if digit < '0' || digit > '9' {
			return 0, errors.New("invalid amount")
		}
	}
	units, err := strconv.ParseInt(whole, 10, 64)
	if err != nil || units < 0 {
		return 0, errors.New("invalid amount")
	}
	cents, err := strconv.ParseInt(fraction, 10, 64)
	if err != nil || cents < 0 || cents > 99 || units > (math.MaxInt64-cents)/100 {
		return 0, errors.New("invalid amount")
	}
	return units*100 + cents, nil
}

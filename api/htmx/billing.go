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
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const stripeAPIBase = "https://api.stripe.com/v1"

type stripeBillingClient interface {
	Checkout(context.Context, stripeCheckoutInput) (string, error)
	Portal(context.Context, string, string) (string, error)
}

type stripeClient struct {
	secret string
	client *http.Client
}

type stripeCheckoutInput struct{ PriceID, UserID, Email, CustomerID, SuccessURL, CancelURL string }

func newStripeClient(secret string) stripeBillingClient {
	return &stripeClient{secret: secret, client: &http.Client{Timeout: 15 * time.Second}}
}

func (client *stripeClient) postForm(ctx context.Context, endpoint string, values url.Values, idempotencyKey string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, stripeAPIBase+endpoint, strings.NewReader(values.Encode()))
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

func (client *stripeClient) Checkout(ctx context.Context, input stripeCheckoutInput) (string, error) {
	values := url.Values{
		"mode": {"subscription"}, "line_items[0][price]": {input.PriceID}, "line_items[0][quantity]": {"1"},
		"success_url": {input.SuccessURL}, "cancel_url": {input.CancelURL}, "client_reference_id": {input.UserID},
		"metadata[user_id]": {input.UserID}, "subscription_data[metadata][user_id]": {input.UserID},
		"allow_promotion_codes": {"true"},
	}
	if input.CustomerID != "" {
		values.Set("customer", input.CustomerID)
	} else {
		values.Set("customer_email", input.Email)
	}
	keyMaterial := fmt.Sprintf("%s\x00%s\x00%d", input.UserID, input.PriceID, time.Now().UTC().Unix()/300)
	key := sha256.Sum256([]byte(keyMaterial))
	return client.postForm(ctx, "/checkout/sessions", values, "objectshare-checkout-"+hex.EncodeToString(key[:]))
}

func (client *stripeClient) Portal(ctx context.Context, customerID, returnURL string) (string, error) {
	return client.postForm(ctx, "/billing_portal/sessions", url.Values{"customer": {customerID}, "return_url": {returnURL}}, "")
}

type planCard struct {
	ID, Name, Description, Price, Storage, Retention string
	DirectLinks                                      bool
}
type plansPageData struct {
	Version, CSRF, Error string
	User                 *db.User
	Plans                []planCard
	BillingEnabled       bool
}

func (handler *Handler) Plans(writer http.ResponseWriter, request *http.Request) {
	var plans []db.PaidPlan
	var err error
	if handler.billing != nil {
		plans, err = handler.billing.PublicPlans(request.Context())
	}
	if err != nil {
		handler.internalError(writer, request, "list paid plans", err)
		return
	}
	cards := make([]planCard, 0, len(plans))
	for _, plan := range plans {
		retention := "No automatic expiry"
		if plan.RetentionDays > 0 {
			retention = fmt.Sprintf("%d days", plan.RetentionDays)
		}
		cards = append(cards, planCard{ID: plan.ID, Name: plan.Name, Description: plan.Description, Price: plan.PriceLabel,
			Storage: humanSize(plan.StorageQuotaBytes), Retention: retention, DirectLinks: plan.DirectLinks})
	}
	handler.render(writer, "plans.html", plansPageData{Version: config.GetVersion(), CSRF: identityCSRF(request), User: identityUser(request), Plans: cards, BillingEnabled: handler.stripe != nil})
}

func (handler *Handler) BillingCheckout(writer http.ResponseWriter, request *http.Request) {
	identity := currentIdentity(request)
	if handler.stripe == nil || handler.billing == nil {
		http.Error(writer, "Billing is unavailable.", http.StatusServiceUnavailable)
		return
	}
	if !handler.verifyAuthenticatedMutationCSRF(writer, request) {
		return
	}
	planID := chi.URLParam(request, "id")
	if _, err := uuid.Parse(planID); err != nil {
		http.NotFound(writer, request)
		return
	}
	plan, err := handler.billing.PlanByID(request.Context(), planID, true)
	if errors.Is(err, db.ErrNotFound) {
		http.NotFound(writer, request)
		return
	}
	if err != nil {
		handler.internalError(writer, request, "get paid plan", err)
		return
	}
	if err := handler.billing.ReserveBillingCheckout(request.Context(), identity.User.ID, plan.ID, time.Now().UTC()); errors.Is(err, db.ErrConflict) {
		http.Error(writer, "A checkout is already in progress for this account. Finish it or retry in 30 minutes.", http.StatusConflict)
		return
	} else if err != nil {
		handler.internalError(writer, request, "reserve billing checkout", err)
		return
	}
	checkoutReserved := true
	defer func() {
		if checkoutReserved {
			_ = handler.billing.ReleaseBillingCheckout(request.Context(), identity.User.ID, plan.ID)
		}
	}()
	customerID := ""
	if subscription, err := handler.billing.SubscriptionForUser(request.Context(), identity.User.ID); err == nil {
		if subscription.Status != "canceled" && subscription.Status != "incomplete_expired" {
			http.Error(writer, "Manage the current subscription from the billing portal before choosing another plan.", http.StatusConflict)
			return
		}
		customerID = subscription.StripeCustomerID
	} else if !errors.Is(err, db.ErrNotFound) {
		handler.internalError(writer, request, "get billing customer", err)
		return
	}
	publicURL := handler.config.Billing.PublicURL
	location, err := handler.stripe.Checkout(request.Context(), stripeCheckoutInput{PriceID: plan.StripePriceID, UserID: identity.User.ID,
		Email: identity.User.Email, CustomerID: customerID, SuccessURL: publicURL + "/account?message=billing-pending", CancelURL: publicURL + "/plans"})
	if err != nil {
		handler.internalError(writer, request, "create Stripe Checkout session", err)
		return
	}
	checkoutReserved = false
	http.Redirect(writer, request, location, http.StatusSeeOther)
}

func (handler *Handler) BillingPortal(writer http.ResponseWriter, request *http.Request) {
	identity := currentIdentity(request)
	if handler.stripe == nil || handler.billing == nil {
		http.Error(writer, "Billing is unavailable.", http.StatusServiceUnavailable)
		return
	}
	if !handler.verifyAuthenticatedMutationCSRF(writer, request) {
		return
	}
	subscription, err := handler.billing.SubscriptionForUser(request.Context(), identity.User.ID)
	if errors.Is(err, db.ErrNotFound) {
		http.Error(writer, "No billing account is available yet.", http.StatusNotFound)
		return
	}
	if err != nil {
		handler.internalError(writer, request, "get billing customer", err)
		return
	}
	location, err := handler.stripe.Portal(request.Context(), subscription.StripeCustomerID, handler.config.Billing.PublicURL+"/account")
	if err != nil {
		handler.internalError(writer, request, "create Stripe billing portal session", err)
		return
	}
	http.Redirect(writer, request, location, http.StatusSeeOther)
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

func (handler *Handler) StripeWebhook(writer http.ResponseWriter, request *http.Request) {
	if handler.stripe == nil || handler.billing == nil {
		http.NotFound(writer, request)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 1024*1024)
	payload, err := io.ReadAll(request.Body)
	if err != nil {
		http.Error(writer, "Invalid webhook body.", http.StatusBadRequest)
		return
	}
	if !verifyStripeSignature(payload, request.Header.Get("Stripe-Signature"), handler.config.Billing.WebhookSecret, time.Now().UTC()) {
		http.Error(writer, "Invalid Stripe signature.", http.StatusBadRequest)
		return
	}
	var event stripeEvent
	if err := json.Unmarshal(payload, &event); err != nil || event.ID == "" || event.Created <= 0 {
		http.Error(writer, "Invalid Stripe event.", http.StatusBadRequest)
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
	plan, err := handler.billing.PlanByStripePrice(request.Context(), priceID)
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
	_, err = handler.billing.ApplyStripeSubscription(request.Context(), db.StripeSubscriptionUpdate{EventID: event.ID,
		EventCreated: event.Created, UserID: userID, PlanID: plan.ID, StripeCustomerID: subscription.Customer,
		StripeSubscriptionID: subscription.ID, Status: subscription.Status, CurrentPeriodEnd: time.Unix(periodEnd, 0).UTC(), CancelAtPeriodEnd: subscription.CancelAtPeriodEnd})
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

type adminPlanRow struct {
	db.PaidPlan
	StorageQuotaGiB string
}
type adminPlansPageData struct {
	Version, CSRF, Error, Message string
	User                          *db.User
	Plans                         []adminPlanRow
}

func (handler *Handler) AdminPlans(writer http.ResponseWriter, request *http.Request) {
	handler.renderAdminPlans(writer, request, "")
}

func (handler *Handler) renderAdminPlans(writer http.ResponseWriter, request *http.Request, formError string) {
	if handler.billing == nil {
		http.Error(writer, "Plan storage is unavailable.", http.StatusServiceUnavailable)
		return
	}
	plans, err := handler.billing.AllPlans(request.Context())
	if err != nil {
		handler.internalError(writer, request, "list administrator plans", err)
		return
	}
	rows := make([]adminPlanRow, 0, len(plans))
	for _, plan := range plans {
		rows = append(rows, adminPlanRow{PaidPlan: plan, StorageQuotaGiB: strconv.FormatFloat(float64(plan.StorageQuotaBytes)/(1024*1024*1024), 'f', -1, 64)})
	}
	identity := currentIdentity(request)
	handler.render(writer, "admin_plans.html", adminPlansPageData{Version: config.GetVersion(), CSRF: identity.Claims.CSRF, User: identity.User, Plans: rows, Error: formError})
}

func (handler *Handler) AdminSavePlan(writer http.ResponseWriter, request *http.Request) {
	identity := currentIdentity(request)
	request.Body = http.MaxBytesReader(writer, request.Body, 32*1024)
	if err := request.ParseForm(); err != nil || !handler.verifyJWTCSRF(writer, request, identity) {
		if err != nil {
			http.Error(writer, "Invalid plan form.", http.StatusBadRequest)
		}
		return
	}
	plan, err := paidPlanFromForm(request)
	if err != nil {
		handler.renderAdminPlans(writer, request, err.Error())
		return
	}
	plan.ID = chi.URLParam(request, "id")
	if plan.ID == "" {
		err = handler.billing.CreatePlan(request.Context(), plan)
	} else if _, parseErr := uuid.Parse(plan.ID); parseErr != nil {
		http.NotFound(writer, request)
		return
	} else {
		err = handler.billing.UpdatePlan(request.Context(), plan)
	}
	if err != nil {
		message := "Could not save the plan. Check that its Stripe Price ID is unique."
		if errors.Is(err, db.ErrConflict) {
			message = "A Stripe Price ID cannot be changed after the plan has subscriptions. Create a new plan and hide the old one instead."
		}
		handler.renderAdminPlans(writer, request, message)
		return
	}
	handler.redirect(writer, request, "/admin/plans")
}

func paidPlanFromForm(request *http.Request) (*db.PaidPlan, error) {
	name, description := strings.TrimSpace(request.FormValue("name")), strings.TrimSpace(request.FormValue("description"))
	priceID, priceLabel := strings.TrimSpace(request.FormValue("stripe_price_id")), strings.TrimSpace(request.FormValue("price_label"))
	if name == "" || len(name) > 80 || len(description) > 500 || !strings.HasPrefix(priceID, "price_") || len(priceID) > 255 || priceLabel == "" || len(priceLabel) > 80 {
		return nil, errors.New("Enter a valid name, Stripe Price ID, price label, and description.")
	}
	quotaGiB, err := strconv.ParseFloat(request.FormValue("storage_quota_gib"), 64)
	if err != nil || quotaGiB <= 0 || quotaGiB > 10240 {
		return nil, errors.New("Storage must be between 0.01 and 10240 GiB.")
	}
	retention, err := strconv.Atoi(request.FormValue("retention_days"))
	if err != nil || retention < 0 || retention > 36500 {
		return nil, errors.New("Retention must be between 0 and 36500 days.")
	}
	sortOrder, err := strconv.Atoi(request.FormValue("sort_order"))
	if err != nil || sortOrder < -10000 || sortOrder > 10000 {
		return nil, errors.New("Sort order must be between -10000 and 10000.")
	}
	return &db.PaidPlan{Name: name, Description: description, StripePriceID: priceID, PriceLabel: priceLabel,
		StorageQuotaBytes: int64(quotaGiB * 1024 * 1024 * 1024), RetentionDays: retention,
		DirectLinks: checked(request, "direct_links"), Active: checked(request, "active"), SortOrder: sortOrder}, nil
}

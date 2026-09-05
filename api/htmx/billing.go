package htmx

import (
	"errors"
	"fmt"
	"math"
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

type planCard struct {
	ID, Name, Description, Price, Storage, Retention, Duration string
	DirectLinks                                                bool
}
type plansPageData struct {
	Version, CSRF, Error, CreditBalance, CreditRequestID string
	User                                                 *db.User
	Plans                                                []planCard
	BillingEnabled                                       bool
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
	creditPurchases := false
	for _, plan := range plans {
		retention := "No automatic expiry"
		if plan.RetentionDays > 0 {
			retention = fmt.Sprintf("%d days", plan.RetentionDays)
		}
		if plan.Price <= 0 || plan.DurationDays <= 0 {
			continue
		}
		cards = append(cards, planCard{ID: plan.ID, Name: plan.Name, Description: plan.Description,
			Price: fmt.Sprintf("%d credits", plan.Price), Duration: fmt.Sprintf("%d days", plan.DurationDays),
			Storage: humanSize(plan.StorageQuotaBytes), Retention: retention, DirectLinks: plan.DirectLinks})
		creditPurchases = true
	}
	user := identityUser(request)
	creditBalance := ""
	if user != nil {
		creditBalance = fmt.Sprintf("%d credits", user.CreditBalance)
	}
	handler.render(writer, "plans.html", plansPageData{Version: config.GetVersion(), CSRF: identityCSRF(request), User: user, Plans: cards, BillingEnabled: creditPurchases, CreditBalance: creditBalance, CreditRequestID: uuid.NewString()})
}

func (handler *Handler) BillingTopUp(writer http.ResponseWriter, request *http.Request) {
	identity := currentIdentity(request)
	if handler.billing == nil || handler.config.Billing == nil {
		http.Error(writer, "Billing is unavailable.", http.StatusServiceUnavailable)
		return
	}
	if !handler.parseAuthForm(writer, request) || !handler.verifyAuthenticatedMutationCSRF(writer, request) {
		return
	}
	gatewayKey := chi.URLParam(request, "gateway")
	gateway := handler.billingGateways[gatewayKey]
	if gateway == nil {
		http.Error(writer, "This billing gateway is unavailable.", http.StatusServiceUnavailable)
		return
	}
	credits, err := strconv.ParseInt(strings.TrimSpace(request.FormValue("credits")), 10, 64)
	settings := handler.config.Billing
	if err != nil || credits < settings.MinTopUpCredits || credits > settings.MaxTopUpCredits || credits > (1<<63-1)/100 {
		http.Error(writer, fmt.Sprintf("Top-up must be a whole number from %d to %d credits.", settings.MinTopUpCredits, settings.MaxTopUpCredits), http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	topUp := &db.CreditTopUp{ID: uuid.NewString(), UserID: identity.User.ID, Gateway: gatewayKey, Credits: credits,
		AmountMinor: credits * 100, Currency: settings.CreditCurrency, ExpiresAt: now.Add(24 * time.Hour)}
	if err := handler.billing.CreateCreditTopUp(request.Context(), topUp); err != nil {
		handler.internalError(writer, request, "reserve credit top-up", err)
		return
	}
	// Keep the reservation on ambiguous gateway failures: a payment may have
	// succeeded remotely and its verified receipt must still be settleable.
	successURL := settings.PublicURL + "/account?message=topup-pending"
	if gatewayKey == db.BillingGatewayPayPal {
		successURL = settings.PublicURL + "/billing/paypal/topup/return?topup=" + url.QueryEscape(topUp.ID)
	}
	result, err := gateway.TopUp(request.Context(), billingTopUpInput{TopUpID: topUp.ID, UserID: identity.User.ID, Email: identity.User.Email,
		Currency: topUp.Currency, Credits: topUp.Credits, AmountMinor: topUp.AmountMinor,
		SuccessURL: successURL, CancelURL: settings.PublicURL + "/account"})
	if err != nil {
		handler.internalError(writer, request, "create "+billingGatewayLabel(gatewayKey)+" credit top-up", err)
		return
	}
	if result.GatewayReference != "" {
		if err := handler.billing.BindCreditTopUp(request.Context(), topUp.ID, gatewayKey, result.GatewayReference); err != nil {
			handler.internalError(writer, request, "bind credit top-up", err)
			return
		}
	}
	http.Redirect(writer, request, result.Location, http.StatusSeeOther)
}

func (handler *Handler) PayPalTopUpReturn(writer http.ResponseWriter, request *http.Request) {
	if handler.billing == nil {
		http.NotFound(writer, request)
		return
	}
	gateway, ok := handler.billingGateways[db.BillingGatewayPayPal].(paypalBillingGateway)
	if !ok {
		http.NotFound(writer, request)
		return
	}
	topUpID, orderID := request.URL.Query().Get("topup"), request.URL.Query().Get("token")
	if _, err := uuid.Parse(topUpID); err != nil || orderID == "" {
		http.Error(writer, "Invalid PayPal return.", http.StatusBadRequest)
		return
	}
	topUp, err := handler.billing.CreditTopUpByID(request.Context(), topUpID)
	if err != nil || topUp.Gateway != db.BillingGatewayPayPal || topUp.GatewayReference == nil || *topUp.GatewayReference != orderID {
		http.Error(writer, "PayPal order does not match this top-up.", http.StatusUnprocessableEntity)
		return
	}
	if topUp.Status == db.CreditTopUpCompleted {
		http.Redirect(writer, request, "/account?message=topup-complete", http.StatusSeeOther)
		return
	}
	if topUp.Status != db.CreditTopUpPending {
		http.Error(writer, "This top-up can no longer be captured.", http.StatusConflict)
		return
	}
	capture, err := gateway.CaptureTopUp(request.Context(), orderID)
	if err != nil {
		handler.internalError(writer, request, "capture PayPal credit top-up", err)
		return
	}
	amountMinor, err := parseMinorAmount(capture.Amount.Value)
	if err != nil || capture.CustomID != topUp.ID || capture.ID == "" || capture.Status != "COMPLETED" {
		http.Error(writer, "PayPal capture does not match this top-up.", http.StatusUnprocessableEntity)
		return
	}
	_, err = handler.billing.ApplyCreditTopUp(request.Context(), db.CreditPayment{TopUpID: topUp.ID, Gateway: db.BillingGatewayPayPal,
		GatewayPaymentID: capture.ID, Currency: capture.Amount.Currency, AmountMinor: amountMinor}, time.Now().UTC())
	if err != nil {
		if errors.Is(err, db.ErrInvalidCredit) || errors.Is(err, db.ErrConflict) {
			http.Error(writer, "PayPal capture does not match this top-up.", http.StatusUnprocessableEntity)
			return
		}
		handler.internalError(writer, request, "apply PayPal credit top-up", err)
		return
	}
	http.Redirect(writer, request, "/account?message=topup-complete", http.StatusSeeOther)
}

func (handler *Handler) BillingPurchaseWithCredit(writer http.ResponseWriter, request *http.Request) {
	identity := currentIdentity(request)
	if handler.billing == nil {
		http.Error(writer, "Billing is unavailable.", http.StatusServiceUnavailable)
		return
	}
	if !handler.parseAuthForm(writer, request) || !handler.verifyAuthenticatedMutationCSRF(writer, request) {
		return
	}
	planID := chi.URLParam(request, "id")
	if _, err := uuid.Parse(planID); err != nil {
		http.NotFound(writer, request)
		return
	}
	requestID := request.FormValue("credit_request_id")
	if _, err := uuid.Parse(requestID); err != nil {
		http.Error(writer, "Reload the plans page before purchasing.", http.StatusBadRequest)
		return
	}
	_, err := handler.billing.PurchasePlanWithCredit(request.Context(), identity.User.ID, planID, requestID, time.Now().UTC())
	if errors.Is(err, db.ErrInsufficientCredit) {
		http.Error(writer, "Your account does not have enough credit for this plan.", http.StatusPaymentRequired)
		return
	}
	if errors.Is(err, db.ErrConflict) {
		http.Error(writer, "Manage or wait for the current active plan before buying a different plan with credit.", http.StatusConflict)
		return
	}
	if errors.Is(err, db.ErrNotFound) {
		http.NotFound(writer, request)
		return
	}
	if errors.Is(err, db.ErrInvalidCredit) {
		http.Error(writer, "This plan is not available for account-credit purchase.", http.StatusUnprocessableEntity)
		return
	}
	if err != nil {
		handler.internalError(writer, request, "purchase plan with credit", err)
		return
	}
	handler.redirect(writer, request, "/account?message=credit-plan")
}

// BillingCheckout retires previously rendered external-subscription forms.
func (handler *Handler) BillingCheckout(writer http.ResponseWriter, request *http.Request) {
	http.Error(writer, "External plan checkout is no longer available. Choose a plan at /plans and purchase it with your account balance.", http.StatusGone)
}

func (handler *Handler) BillingPortal(writer http.ResponseWriter, request *http.Request) {
	identity := currentIdentity(request)
	if handler.billing == nil {
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
	gateway := handler.billingGateways[subscription.Gateway]
	if gateway == nil {
		http.Error(writer, billingGatewayLabel(subscription.Gateway)+" billing is unavailable.", http.StatusServiceUnavailable)
		return
	}
	location, err := gateway.Portal(request.Context(), subscription, handler.config.Billing.PublicURL+"/account")
	if err != nil {
		handler.internalError(writer, request, "open "+billingGatewayLabel(subscription.Gateway)+" billing management", err)
		return
	}
	http.Redirect(writer, request, location, http.StatusSeeOther)
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
		message := "Could not save the plan. Check its price and access duration and try again."
		handler.renderAdminPlans(writer, request, message)
		return
	}
	handler.redirect(writer, request, "/admin/plans")
}

func paidPlanFromForm(request *http.Request) (*db.PaidPlan, error) {
	name, description := strings.TrimSpace(request.FormValue("name")), strings.TrimSpace(request.FormValue("description"))
	if name == "" || len(name) > 80 || len(description) > 500 {
		return nil, errors.New("Enter a valid name and description.")
	}
	quotaGiB, err := strconv.ParseFloat(request.FormValue("storage_quota_gib"), 64)
	if err != nil || math.IsNaN(quotaGiB) || quotaGiB < 0.01 || quotaGiB > 10240 {
		return nil, errors.New("Storage must be between 0.01 and 10240 GiB.")
	}
	retention, err := strconv.Atoi(request.FormValue("retention_days"))
	if err != nil || retention < 0 || retention > 36500 {
		return nil, errors.New("Retention must be between 0 and 36500 days.")
	}
	price, err := strconv.ParseInt(request.FormValue("price"), 10, 64)
	if err != nil || price <= 0 || price > 1_000_000_000 {
		return nil, errors.New("Price must be a whole number from 1 to 1000000000 credits.")
	}
	duration, err := strconv.Atoi(request.FormValue("duration_days"))
	if err != nil || duration <= 0 || duration > 36500 {
		return nil, errors.New("Access duration must be between 1 and 36500 days.")
	}
	sortOrder, err := strconv.Atoi(request.FormValue("sort_order"))
	if err != nil || sortOrder < -10000 || sortOrder > 10000 {
		return nil, errors.New("Sort order must be between -10000 and 10000.")
	}
	return &db.PaidPlan{Name: name, Description: description,
		StorageQuotaBytes: int64(quotaGiB * 1024 * 1024 * 1024), RetentionDays: retention,
		DirectLinks: checked(request, "direct_links"), Price: price, DurationDays: duration,
		Active: checked(request, "active"), SortOrder: sortOrder}, nil
}

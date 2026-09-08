package htmx

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/AutisticShark/ObjectShare/email"
	invoicepdf "github.com/AutisticShark/ObjectShare/invoice"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type invoicePageData struct {
	VerificationRequired         bool
	Version, CSRF                string
	User                         *db.User
	Invoice                      *db.Invoice
	Invoices                     []db.Invoice
	Gateways                     []billingGatewayOption
	CanPay                       bool
	Page, NextPage, PreviousPage int
	HasNext                      bool
}

func (handler *Handler) invoiceRepo(writer http.ResponseWriter) db.InvoiceRepository {
	repo, _ := handler.billing.(db.InvoiceRepository)
	if repo == nil {
		http.Error(writer, "Invoice storage is unavailable.", http.StatusServiceUnavailable)
	}
	return repo
}

func (handler *Handler) invoiceFailure(writer http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, db.ErrNotFound):
		http.NotFound(writer, request)
	case errors.Is(err, db.ErrInsufficientCredit):
		http.Error(writer, "Your account does not have enough credit to pay this invoice.", http.StatusPaymentRequired)
	case errors.Is(err, db.ErrConflict):
		http.Error(writer, "This invoice cannot be paid with this method. Check its payment status and your current plan. A gateway payment already in progress must finish before another purchase.", http.StatusConflict)
	case errors.Is(err, db.ErrInvalidCredit):
		http.Error(writer, "Invalid invoice request. Reload the plans page.", http.StatusBadRequest)
	default:
		handler.internalError(writer, request, "invoice operation", err)
	}
}

func (handler *Handler) CreateInvoice(writer http.ResponseWriter, request *http.Request) {
	if !handler.parseAuthForm(writer, request) || !handler.verifyAuthenticatedMutationCSRF(writer, request) {
		return
	}
	if !handler.purchaseAllowed(writer, request) {
		return
	}
	repo := handler.invoiceRepo(writer)
	if repo == nil {
		return
	}
	if !handler.allowRequest(writer, request, "invoice-create", 20) {
		return
	}
	if _, err := uuid.Parse(chi.URLParam(request, "id")); err != nil {
		http.NotFound(writer, request)
		return
	}
	currency := "USD"
	if handler.config.Billing != nil {
		currency = handler.config.Billing.CreditCurrency
	}
	invoice, err := repo.CreatePlanInvoice(request.Context(), identityUser(request).ID, chi.URLParam(request, "id"), request.FormValue("credit_request_id"), currency, time.Now().UTC())
	if err != nil {
		handler.invoiceFailure(writer, request, err)
		return
	}
	handler.redirect(writer, request, "/invoices/"+invoice.ID)
}

func (handler *Handler) Invoices(writer http.ResponseWriter, request *http.Request) {
	repo := handler.invoiceRepo(writer)
	if repo == nil {
		return
	}
	page := 0
	if raw := request.URL.Query().Get("page"); raw != "" {
		var err error
		page, err = strconv.Atoi(raw)
		if err != nil || page < 0 || page > 100000 {
			http.Error(writer, "Invalid page.", 400)
			return
		}
	}
	invoices, err := repo.InvoicesForUser(request.Context(), identityUser(request).ID, page)
	if err != nil {
		handler.invoiceFailure(writer, request, err)
		return
	}
	writer.Header().Set("Cache-Control", "private, no-store")
	handler.render(writer, "invoices.html", invoicePageData{Version: config.GetVersion(), User: identityUser(request), CSRF: identityCSRF(request), Invoices: invoices, Page: page, NextPage: page + 1, PreviousPage: page - 1, HasNext: len(invoices) == 25})
}

func (handler *Handler) ownedInvoice(writer http.ResponseWriter, request *http.Request) *db.Invoice {
	repo := handler.invoiceRepo(writer)
	if repo == nil {
		return nil
	}
	id := chi.URLParam(request, "id")
	if _, err := uuid.Parse(id); err != nil {
		http.NotFound(writer, request)
		return nil
	}
	invoice, err := repo.InvoiceForUser(request.Context(), identityUser(request).ID, id)
	if err != nil {
		handler.invoiceFailure(writer, request, err)
		return nil
	}
	writer.Header().Set("Cache-Control", "private, no-store")
	return invoice
}

func (handler *Handler) Invoice(writer http.ResponseWriter, request *http.Request) {
	invoice := handler.ownedInvoice(writer, request)
	if invoice == nil {
		return
	}
	gateways := []billingGatewayOption{}
	for _, gateway := range billingGatewayOptions() {
		if handler.billingGateways[gateway.Key] != nil && (invoice.Gateway == "" || invoice.Gateway == gateway.Key) {
			gateways = append(gateways, gateway)
		}
	}
	verificationRequired := invoice.Kind == "plan" && handler.verificationSettings().RequireForPurchases && identityUser(request).EmailVerifiedAt == nil
	handler.render(writer, "invoice.html", invoicePageData{Version: config.GetVersion(), User: identityUser(request), CSRF: identityCSRF(request), Invoice: invoice, Gateways: gateways, VerificationRequired: verificationRequired, CanPay: !verificationRequired && invoice.Status == "pending" && invoice.ExpiresAt.After(time.Now().UTC())})
}

func (handler *Handler) InvoicePDF(writer http.ResponseWriter, request *http.Request) {
	invoice := handler.ownedInvoice(writer, request)
	if invoice == nil {
		return
	}
	data, err := invoicepdf.PDF(*invoice, handler.config.Branding.Display().SiteName)
	if err != nil {
		handler.internalError(writer, request, "render invoice PDF", err)
		return
	}
	writer.Header().Set("Content-Type", "application/pdf")
	writer.Header().Set("Content-Disposition", `attachment; filename="invoice-`+invoice.ID+`.pdf"`)
	_, _ = writer.Write(data)
}

func (handler *Handler) PayInvoice(writer http.ResponseWriter, request *http.Request) {
	if !handler.parseAuthForm(writer, request) || !handler.verifyAuthenticatedMutationCSRF(writer, request) {
		return
	}
	invoice := handler.ownedInvoice(writer, request)
	if invoice == nil {
		return
	}
	if invoice.Kind == "plan" && !handler.purchaseAllowed(writer, request) {
		return
	}
	repo := handler.billing.(db.InvoiceRepository)
	gatewayKey := request.FormValue("gateway")
	if gatewayKey == db.BillingGatewayCredit {
		if err := repo.PayInvoiceCredit(request.Context(), identityUser(request).ID, invoice.ID, time.Now().UTC()); err != nil {
			handler.invoiceFailure(writer, request, err)
			return
		}
		handler.redirect(writer, request, "/invoices/"+invoice.ID)
		return
	}
	gateway := handler.billingGateways[gatewayKey]
	if gateway == nil || handler.config.Billing == nil {
		http.Error(writer, "This payment gateway is unavailable.", 503)
		return
	}
	payment, err := repo.ReserveInvoiceGateway(request.Context(), identityUser(request).ID, invoice.ID, gatewayKey, time.Now().UTC())
	if err != nil {
		handler.invoiceFailure(writer, request, err)
		return
	}
	if payment.CheckoutURL != "" {
		http.Redirect(writer, request, payment.CheckoutURL, http.StatusSeeOther)
		return
	}
	base := handler.config.Billing.PublicURL
	success := base + "/invoices/" + invoice.ID
	if gatewayKey == db.BillingGatewayPayPal {
		success = base + "/billing/paypal/topup/return?topup=" + url.QueryEscape(payment.ID)
	}
	result, err := gateway.TopUp(request.Context(), billingTopUpInput{TopUpID: payment.ID, UserID: invoice.UserID, Email: invoice.Email, Currency: invoice.Currency, Credits: invoice.Credits, AmountMinor: invoice.AmountMinor, Description: "Invoice " + invoice.ID + ": " + invoice.Name, SuccessURL: success, CancelURL: base + "/invoices/" + invoice.ID})
	if err != nil {
		handler.internalError(writer, request, "create invoice payment", err)
		return
	}
	if err = repo.BindInvoiceCheckout(request.Context(), invoice.UserID, invoice.ID, gatewayKey, result.GatewayReference, result.Location); err != nil {
		handler.invoiceFailure(writer, request, err)
		return
	}
	http.Redirect(writer, request, result.Location, http.StatusSeeOther)
}

// RunInvoiceEmails is a durable, leased outbox. Provider acceptance is recorded
// separately from payment; a crash after acceptance can produce a duplicate email.
func (handler *Handler) RunInvoiceEmails(ctx context.Context) {
	repo, _ := handler.billing.(db.InvoiceRepository)
	if repo == nil || handler.emailSender == nil {
		return
	}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		if handler.config.Email != nil && handler.config.Email.Provider != "none" {
			for range 20 {
				invoice, err := repo.ClaimInvoiceEmail(ctx, time.Now().UTC())
				if errors.Is(err, db.ErrNotFound) {
					break
				}
				if err != nil {
					handler.logger.Error("claim invoice email failed")
					break
				}
				data, sendErr := invoicepdf.PDF(*invoice, handler.config.Branding.Display().SiteName)
				if sendErr == nil {
					sendErr = handler.emailSender.Send(ctx, email.Message{To: invoice.Email, Subject: "Payment confirmed - invoice " + invoice.ID,
						Text:        fmt.Sprintf("Your payment for %s is confirmed. Invoice %s is paid. The invoice PDF is attached. You can view your invoices from your account on the website.", invoice.Name, invoice.ID),
						Attachments: []email.Attachment{{Filename: "invoice-" + invoice.ID + ".pdf", ContentType: "application/pdf", Data: data}}})
				}
				if sendErr != nil {
					handler.logger.Error("invoice email delivery failed; will retry", "invoice_id", invoice.ID)
				}
				if err = repo.FinishInvoiceEmail(ctx, invoice.ID, invoice.EmailLease, sendErr == nil, time.Now().UTC()); err != nil {
					handler.logger.Error("record invoice email delivery failed", "invoice_id", invoice.ID)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

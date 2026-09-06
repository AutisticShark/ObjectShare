package htmx

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/AutisticShark/ObjectShare/db"
)

// Legacy Stripe subscription receipts use the pinned 2024-06-20 webhook schema.
func (handler *Handler) stripePaidInvoice(writer http.ResponseWriter, request *http.Request, event stripeEvent) {
	var paid struct {
		ID, Status, Subscription, Currency string
		AmountPaid                         int64 `json:"amount_paid"`
		StatusTransitions                  struct {
			PaidAt int64 `json:"paid_at"`
		} `json:"status_transitions"`
		Parent struct {
			SubscriptionDetails struct {
				Subscription string `json:"subscription"`
			} `json:"subscription_details"`
		} `json:"parent"`
		Lines struct {
			Data []struct {
				Type      string
				Proration bool
				Price     struct{ ID string }
				Period    struct{ Start, End int64 }
			}
			HasMore bool `json:"has_more"`
		} `json:"lines"`
	}
	if json.Unmarshal(event.Data.Object, &paid) != nil || paid.ID == "" || paid.Status != "paid" || paid.StatusTransitions.PaidAt <= 0 {
		http.Error(writer, "Invalid paid Stripe invoice.", 422)
		return
	}
	if paid.Subscription == "" {
		paid.Subscription = paid.Parent.SubscriptionDetails.Subscription
	}
	if paid.Subscription == "" {
		writer.WriteHeader(204)
		return
	}
	// Existing ObjectShare subscriptions have exactly one recurring price. Do not
	// infer access from prorations, truncated line lists, or unrelated invoice items.
	if paid.Lines.HasMore || len(paid.Lines.Data) != 1 || paid.Lines.Data[0].Type != "subscription" || paid.Lines.Data[0].Proration {
		http.Error(writer, "Unsupported subscription invoice lines.", 422)
		return
	}
	repo := handler.invoiceRepo(writer)
	if repo == nil {
		return
	}
	line := paid.Lines.Data[0]
	plan, err := handler.billing.PlanByGatewayID(request.Context(), db.BillingGatewayStripe, line.Price.ID)
	if err != nil {
		handler.invoiceFailure(writer, request, err)
		return
	}
	err = repo.ApplyLegacyInvoicePayment(request.Context(), db.LegacyInvoicePayment{Gateway: db.BillingGatewayStripe, PlanID: plan.ID, PaymentID: paid.ID, SubscriptionID: paid.Subscription, Currency: paid.Currency, AmountMinor: paid.AmountPaid,
		PeriodStart: time.Unix(line.Period.Start, 0).UTC(), PeriodEnd: time.Unix(line.Period.End, 0).UTC(), PaidAt: time.Unix(paid.StatusTransitions.PaidAt, 0).UTC()}, time.Now().UTC())
	if err != nil {
		handler.internalError(writer, request, "apply paid subscription invoice", err)
		return
	}
	writer.WriteHeader(204)
}

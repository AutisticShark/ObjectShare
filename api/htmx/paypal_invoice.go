package htmx

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/AutisticShark/ObjectShare/db"
)

func (handler *Handler) paypalPaidInvoice(writer http.ResponseWriter, request *http.Request, gateway paypalBillingGateway, payload []byte) {
	var sale struct {
		Resource struct {
			ID, State   string
			AgreementID string `json:"billing_agreement_id"`
			CreateTime  string `json:"create_time"`
			Amount      struct{ Total, Currency string }
		}
	}
	if json.Unmarshal(payload, &sale) != nil || sale.Resource.State != "completed" || sale.Resource.ID == "" || sale.Resource.AgreementID == "" {
		http.Error(writer, "Invalid paid PayPal subscription sale.", 422)
		return
	}
	amount, err := parseMinorAmount(sale.Resource.Amount.Total)
	if err != nil {
		http.Error(writer, "Invalid PayPal sale amount.", 422)
		return
	}
	paidAt, err := time.Parse(time.RFC3339, sale.Resource.CreateTime)
	if err != nil {
		http.Error(writer, "Invalid PayPal sale time.", 422)
		return
	}
	details, err := gateway.SubscriptionDetails(request.Context(), sale.Resource.AgreementID)
	if err != nil || details.ID != sale.Resource.AgreementID {
		http.Error(writer, "Cannot verify PayPal subscription period.", 502)
		return
	}
	periodEnd := paidAt.Add(time.Second)
	lastPaid, lastErr := time.Parse(time.RFC3339, details.BillingInfo.LastPayment.Time)
	if lastErr == nil && lastPaid.Sub(paidAt).Abs() < time.Minute {
		periodEnd, err = time.Parse(time.RFC3339, details.BillingInfo.NextBillingTime)
		if err != nil {
			http.Error(writer, "Missing paid PayPal subscription period.", 422)
			return
		}
	}
	repo := handler.invoiceRepo(writer)
	if repo == nil {
		return
	}
	plan, err := handler.billing.PlanByGatewayID(request.Context(), db.BillingGatewayPayPal, details.PlanID)
	if err != nil {
		handler.invoiceFailure(writer, request, err)
		return
	}
	err = repo.ApplyLegacyInvoicePayment(request.Context(), db.LegacyInvoicePayment{Gateway: db.BillingGatewayPayPal, PlanID: plan.ID, PaymentID: sale.Resource.ID, SubscriptionID: sale.Resource.AgreementID, Currency: sale.Resource.Amount.Currency, AmountMinor: amount, PeriodStart: paidAt, PeriodEnd: periodEnd, PaidAt: paidAt}, time.Now().UTC())
	if err != nil {
		handler.internalError(writer, request, "apply paid PayPal subscription invoice", err)
		return
	}
	writer.WriteHeader(204)
}

package htmx

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
)

func TestCreditTemplatesRenderFormsHistoryAndPrepaidState(t *testing.T) {
	parsed, err := parseTemplates(os.DirFS("../.."), config.BrandingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	user := &db.User{ID: "user", Email: "user@example.com", Role: db.RoleAdmin}
	for _, test := range []struct {
		name               string
		data               any
		contains, excludes []string
	}{
		{"account.html", accountPageData{User: user, CSRF: "csrf", CreditBalance: "0 credits", CreditCurrency: "USD", MinTopUpCredits: 5, MaxTopUpCredits: 1000,
			TopUpGateways: billingGatewayOptions(), CreditPlan: true, BillingAccount: true, PlanActive: true,
			CreditTransactions: []creditTransactionRow{{Description: "<script>alert(1)</script>", Delta: "+5", Balance: "5", Positive: true}}},
			[]string{"0 credits", `action="/billing/topup/stripe"`, `action="/billing/topup/paypal"`, `min="5" max="1000"`, "Prepaid plan", "&lt;script&gt;"},
			[]string{`action="/billing/portal"`, "<script>alert(1)</script>"}},
		{"plans.html", plansPageData{User: user, CreditBalance: "25 credits", Plans: []planCard{{ID: "plan", Price: "10 credits", Duration: "30 days", RequestID: "request-key"}, {ID: "other", Price: "20 credits", Duration: "30 days", RequestID: "other-key"}}},
			[]string{`action="/billing/invoices/plan"`, `name="credit_request_id" value="request-key"`, `action="/billing/invoices/other"`, `name="credit_request_id" value="other-key"`, "10 credits", "30 days"}, []string{`action="/billing/checkout/`, "Subscribe with", "Unknown gateway"}},
		{"admin_users.html", adminPageData{User: user, Users: []adminUserRow{{ID: "target", CreditBalance: "-7 credits", CreditRequestID: "adjustment-key"}}},
			[]string{`action="/admin/users/target/credit"`, `name="credit_request_id" value="adjustment-key"`, "-7 credits", `name="credit_description"`}, nil},
		{"admin_plans.html", adminPlansPageData{User: user, Plans: []adminPlanRow{{PaidPlan: db.PaidPlan{ID: "plan", Price: 10, DurationDays: 30}}}},
			[]string{`name="price"`, `name="duration_days"`, `value="10"`, `value="30"`}, []string{"Credit price", "Displayed price", `name="gateway"`, `name="gateway_plan_id"`, `name="price_label"`, `name="credit_price"`}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := parsed.ExecuteTemplate(&output, test.name, test.data); err != nil {
				t.Fatal(err)
			}
			for _, expected := range test.contains {
				if !strings.Contains(output.String(), expected) {
					t.Errorf("missing %q", expected)
				}
			}
			for _, forbidden := range test.excludes {
				if strings.Contains(output.String(), forbidden) {
					t.Errorf("unexpected %q", forbidden)
				}
			}
		})
	}
}

// PostgreSQL returns timestamps in the process's local zone. Billing pages label
// times as UTC, so they must convert them, matching the invoice PDF.
func TestBillingTemplatesShowTimesInUTC(t *testing.T) {
	parsed, err := parseTemplates(os.DirFS("../.."), config.BrandingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	user := &db.User{ID: "user", Email: "user@example.com", Role: db.RoleAdmin}
	taipei := time.FixedZone("Asia/Taipei", 8*60*60)
	created := time.Date(2026, 10, 4, 20, 0, 0, 0, taipei) // 12:00 UTC
	paidAt := created.Add(time.Hour)
	pending := db.Invoice{ID: "pending", Name: "Plus", Kind: "plan", Status: "pending", Currency: "USD", CreatedAt: created, ExpiresAt: created.Add(24 * time.Hour)}
	paid := pending
	paid.ID, paid.Status, paid.PaidAt = "paid", "paid", &paidAt
	for _, test := range []struct {
		name     string
		data     any
		contains []string
	}{
		{"invoice.html", invoicePageData{User: user, Invoice: &pending}, []string{"Issued 2026-10-04 12:00 UTC", "Payment window ends 2026-10-05 12:00 UTC"}},
		{"invoice.html", invoicePageData{User: user, Invoice: &paid}, []string{"Issued 2026-10-04 12:00 UTC", "Payment confirmed on 2026-10-04 13:00 UTC"}},
		{"invoices.html", invoicePageData{User: user, Invoices: []db.Invoice{pending}}, []string{"Issued (UTC)", "<td>2026-10-04 12:00</td>"}},
		{"admin_invoices.html", workspacePageData{User: user, Page: 1, Invoices: []db.Invoice{pending}}, []string{"2026-10-04 12:00 UTC", "Window ends 2026-10-05 12:00 UTC"}},
	} {
		var output bytes.Buffer
		if err := parsed.ExecuteTemplate(&output, test.name, test.data); err != nil {
			t.Fatal(err)
		}
		body := output.String()
		for _, value := range test.contains {
			if !strings.Contains(body, value) {
				t.Errorf("%s does not contain %q", test.name, value)
			}
		}
		if strings.Contains(body, "20:00") || strings.Contains(body, "21:00") {
			t.Errorf("%s shows a local time as UTC", test.name)
		}
	}
}

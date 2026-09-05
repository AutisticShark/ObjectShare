package htmx

import (
	"bytes"
	"os"
	"strings"
	"testing"

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
			[]string{"0 credits", `action="/billing/topup/stripe"`, `action="/billing/topup/paypal"`, `min="5" max="1000"`, "Purchased with account credit", "&lt;script&gt;"},
			[]string{`action="/billing/portal"`, "<script>alert(1)</script>"}},
		{"plans.html", plansPageData{User: user, CreditBalance: "25 credits", CreditRequestID: "request-key", Plans: []planCard{{ID: "plan", Price: "10 credits", Duration: "30 days"}}},
			[]string{`action="/billing/credit/plan"`, `name="credit_request_id" value="request-key"`, "10 credits", "30 days"}, []string{`action="/billing/checkout/`, "Subscribe with", "Unknown gateway"}},
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

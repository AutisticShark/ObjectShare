package web

import (
	"strings"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/db"
)

func TestCreditPagesCarryBalanceGatewaysHistoryAndRequestIDs(t *testing.T) {
	user := &db.User{ID: "user", Email: "user@example.com", Role: db.RoleAdmin}
	const script = "<script>alert(1)</script>"
	for _, test := range []struct {
		name  string
		page  string
		data  any
		check func(t *testing.T, data map[string]any, body string)
	}{
		{"account", "account.html", accountPageData{User: user, CSRF: "csrf", CreditBalance: "0 credits", CreditCurrency: "USD", MinTopUpCredits: 5, MaxTopUpCredits: 1000,
			TopUpGateways: billingGatewayOptions(), CreditPlan: true, BillingAccount: true, PlanActive: true,
			CreditTransactions: []creditTransactionRow{{Description: script, Delta: "+5", Balance: "5", Positive: true}}},
			func(t *testing.T, data map[string]any, body string) {
				if data["CreditBalance"] != "0 credits" || data["MinTopUpCredits"] != float64(5) || data["MaxTopUpCredits"] != float64(1000) || data["CreditPlan"] != true || data["CSRF"] != "csrf" {
					t.Errorf("credit state = %v", data)
				}
				keys := map[string]bool{}
				for _, gateway := range data["TopUpGateways"].([]any) {
					keys[gateway.(map[string]any)["Key"].(string)] = true
				}
				if !keys["stripe"] || !keys["paypal"] {
					t.Errorf("top-up gateways = %v", keys)
				}
				history := data["CreditTransactions"].([]any)
				if len(history) != 1 || history[0].(map[string]any)["Description"] != script {
					t.Errorf("history = %v", history)
				}
				if strings.Contains(body, script) {
					t.Error("transaction description was not escaped")
				}
			}},
		{"plans", "plans.html", plansPageData{User: user, CreditBalance: "25 credits", Plans: []planCard{{ID: "plan", Price: "10 credits", Duration: "30 days", RequestID: "request-key"}, {ID: "other", Price: "20 credits", Duration: "30 days", RequestID: "other-key"}}},
			func(t *testing.T, data map[string]any, _ string) {
				plans := data["Plans"].([]any)
				if data["CreditBalance"] != "25 credits" || len(plans) != 2 {
					t.Fatalf("plans = %v", data)
				}
				for i, want := range []struct{ id, price, request string }{{"plan", "10 credits", "request-key"}, {"other", "20 credits", "other-key"}} {
					card := plans[i].(map[string]any)
					if card["ID"] != want.id || card["Price"] != want.price || card["Duration"] != "30 days" || card["RequestID"] != want.request {
						t.Errorf("card %d = %v", i, card)
					}
				}
			}},
		{"admin users", "admin_users.html", adminPageData{User: user, Users: []adminUserRow{{ID: "target", CreditBalance: "-7 credits", CreditRequestID: "adjustment-key"}}},
			func(t *testing.T, data map[string]any, _ string) {
				rows := data["Users"].([]any)
				if len(rows) != 1 {
					t.Fatalf("rows = %v", rows)
				}
				row := rows[0].(map[string]any)
				if row["ID"] != "target" || row["CreditBalance"] != "-7 credits" || row["CreditRequestID"] != "adjustment-key" {
					t.Errorf("row = %v", row)
				}
			}},
		{"admin plans", "admin_plans.html", adminPlansPageData{User: user, Plans: []adminPlanRow{{PaidPlan: db.PaidPlan{ID: "plan", Price: 10, DurationDays: 30, LegacyPriceLabel: "$999 / month"}}}},
			func(t *testing.T, data map[string]any, body string) {
				plans := data["Plans"].([]any)
				if len(plans) != 1 {
					t.Fatalf("plans = %v", plans)
				}
				plan := plans[0].(map[string]any)
				if plan["ID"] != "plan" || plan["Price"] != float64(10) || plan["DurationDays"] != float64(30) {
					t.Errorf("plan = %v", plan)
				}
				if strings.Contains(body, "$999") {
					t.Error("the legacy price label was exposed")
				}
			}},
	} {
		t.Run(test.name, func(t *testing.T) {
			output, err := (&Handler{}).frontendPage(test.page, test.data)
			if err != nil {
				t.Fatal(err)
			}
			page, data := pageOf(t, string(output))
			if page != strings.TrimSuffix(test.page, ".html") {
				t.Fatalf("page = %q", page)
			}
			test.check(t, data, string(output))
		})
	}
}

// PostgreSQL returns timestamps in the process's local zone. Billing pages hand
// them to the frontend as UTC, which labels them as UTC, so the projection must
// convert them, matching the invoice PDF.
func TestBillingPagesCarryTimesInUTC(t *testing.T) {
	user := &db.User{ID: "user", Email: "user@example.com", Role: db.RoleAdmin}
	taipei := time.FixedZone("Asia/Taipei", 8*60*60)
	created := time.Date(2026, 10, 4, 20, 0, 0, 0, taipei) // 12:00 UTC
	paidAt := created.Add(time.Hour)
	pending := db.Invoice{ID: "pending", Name: "Plus", Kind: "plan", Status: "pending", Currency: "USD", CreatedAt: created, ExpiresAt: created.Add(24 * time.Hour)}
	paid := pending
	paid.ID, paid.Status, paid.PaidAt = "paid", "paid", &paidAt
	invoiceOf := func(data map[string]any) map[string]any {
		return data["Invoice"].(map[string]any)
	}
	firstInvoice := func(data map[string]any) map[string]any {
		return data["Invoices"].([]any)[0].(map[string]any)
	}
	for _, test := range []struct {
		name    string
		data    any
		invoice func(map[string]any) map[string]any
		want    map[string]string
	}{
		{"invoice.html", invoicePageData{User: user, Invoice: &pending}, invoiceOf, map[string]string{"CreatedAt": "2026-10-04T12:00:00Z", "ExpiresAt": "2026-10-05T12:00:00Z"}},
		{"invoice.html", invoicePageData{User: user, Invoice: &paid}, invoiceOf, map[string]string{"CreatedAt": "2026-10-04T12:00:00Z", "PaidAt": "2026-10-04T13:00:00Z"}},
		{"invoices.html", invoicePageData{User: user, Invoices: []db.Invoice{pending}}, firstInvoice, map[string]string{"CreatedAt": "2026-10-04T12:00:00Z"}},
		{"admin_invoices.html", workspacePageData{User: user, Page: 1, Invoices: []db.Invoice{pending}}, firstInvoice, map[string]string{"CreatedAt": "2026-10-04T12:00:00Z", "ExpiresAt": "2026-10-05T12:00:00Z"}},
	} {
		output, err := (&Handler{}).frontendPage(test.name, test.data)
		if err != nil {
			t.Fatal(err)
		}
		body := string(output)
		_, data := pageOf(t, body)
		invoice := test.invoice(data)
		for field, value := range test.want {
			if invoice[field] != value {
				t.Errorf("%s %s = %v, want %s", test.name, field, invoice[field], value)
			}
		}
		if strings.Contains(body, "+08:00") || strings.Contains(body, "T20:00") || strings.Contains(body, "T21:00") {
			t.Errorf("%s carries a local time", test.name)
		}
	}
}

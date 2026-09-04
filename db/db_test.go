package db

import (
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"gorm.io/gorm/schema"
)

func TestUploadQuotaComparisonDoesNotOverflow(t *testing.T) {
	if exceedsQuota(math.MaxInt64-5, 10, math.MaxInt64) != true {
		t.Fatal("overflowing reservation should exceed the quota")
	}
	if exceedsQuota(100, 100, 0) {
		t.Fatal("zero quota should be unlimited")
	}
	err := &UploadQuotaError{Scope: "user", Used: 90, Limit: 100, Requested: 11}
	if !errors.Is(err, ErrUploadQuota) {
		t.Fatal("quota error does not unwrap to ErrUploadQuota")
	}
}

func TestUserUploadQuotaMigrationMetadata(t *testing.T) {
	parsed, err := schema.Parse(&User{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	field := parsed.FieldsByDBName["upload_quota_bytes"]
	if field == nil || !field.NotNull || !field.HasDefaultValue || field.DefaultValueInterface != int64(0) {
		t.Fatalf("unsafe upload quota field metadata: %#v", field)
	}
	check, ok := parsed.ParseCheckConstraints()["chk_users_upload_quota_bytes_nonnegative"]
	if !ok || check.Constraint != "upload_quota_bytes >= 0" {
		t.Fatalf("missing nonnegative quota constraint: %#v", parsed.ParseCheckConstraints())
	}
}

func TestUserDarkModeMigrationMetadata(t *testing.T) {
	parsed, err := schema.Parse(&User{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	field := parsed.FieldsByDBName["dark_mode"]
	if field == nil || !field.NotNull || !field.HasDefaultValue || field.DefaultValueInterface != false {
		t.Fatalf("unsafe dark mode field metadata: %#v", field)
	}
}

func TestPaidStatusAndRetentionClaimMigrationMetadata(t *testing.T) {
	users, err := schema.Parse(&User{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	paid := users.FieldsByDBName["is_paid"]
	if paid == nil || !paid.NotNull || !paid.HasDefaultValue || paid.DefaultValueInterface != false {
		t.Fatalf("unsafe paid-status field metadata: %#v", paid)
	}
	files, err := schema.Parse(&FileList{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	claim := files.FieldsByDBName["retention_claimed_at"]
	if claim == nil || claim.TagSettings["INDEX"] == "" {
		t.Fatalf("retention claim is not indexed: %#v", claim)
	}
}

func TestRetentionEligibilityKeepsPaidAccountsOutOfCleanup(t *testing.T) {
	guestBefore := time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)
	unpaidBefore := time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	query, arguments := retentionEligibilitySQLAt(now, &guestBefore, &unpaidBefore)
	for _, clause := range []string{"f.file_owner IS NULL", "f.file_owner IS NOT NULL", "u.id = f.file_owner", "u.is_paid = FALSE", "subscriptions AS s", "p.retention_days"} {
		if !strings.Contains(query, clause) {
			t.Fatalf("retention eligibility omitted %q: %s", clause, query)
		}
	}
	if len(arguments) != 5 || arguments[0] != guestBefore || arguments[1] != now || arguments[2] != now || arguments[3] != now || arguments[4] != unpaidBefore {
		t.Fatalf("retention cutoffs = %#v", arguments)
	}
	disabled, arguments := retentionEligibilitySQLAt(now, nil, nil)
	if disabled != "FALSE" || len(arguments) != 0 {
		t.Fatalf("disabled retention produced %q with %#v", disabled, arguments)
	}
}

func TestSubscriptionBenefitsRequireActiveStatusAndFuturePeriod(t *testing.T) {
	now := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	if !subscriptionActive("active", now.Add(time.Hour), now) || !subscriptionActive("trialing", now.Add(time.Hour), now) {
		t.Fatal("active subscription statuses did not receive benefits")
	}
	if subscriptionActive("past_due", now.Add(time.Hour), now) || subscriptionActive("active", now, now) {
		t.Fatal("inactive or expired subscription received benefits")
	}
}

func TestBillingModelsUseGatewayScopedIdentifiers(t *testing.T) {
	plan, err := schema.Parse(&PaidPlan{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"gateway", "gateway_plan_id"} {
		if plan.FieldsByDBName[name] == nil || !plan.FieldsByDBName[name].NotNull {
			t.Fatalf("paid plan %s is missing or nullable", name)
		}
	}
	subscription, err := schema.Parse(&Subscription{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"gateway", "customer_id", "gateway_subscription_id"} {
		if subscription.FieldsByDBName[name] == nil || !subscription.FieldsByDBName[name].NotNull {
			t.Fatalf("subscription %s is missing or nullable", name)
		}
	}
}

func TestCreditModelsHaveSafeMigrationMetadata(t *testing.T) {
	user, err := schema.Parse(&User{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	balance := user.FieldsByDBName["credit_balance"]
	if balance == nil || !balance.NotNull || !balance.HasDefaultValue || balance.DefaultValueInterface != int64(0) {
		t.Fatalf("unsafe credit balance metadata: %#v", balance)
	}
	plan, err := schema.Parse(&PaidPlan{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"credit_price", "credit_duration_days"} {
		field := plan.FieldsByDBName[name]
		if field == nil || !field.NotNull || !field.HasDefaultValue {
			t.Fatalf("unsafe plan credit field %s: %#v", name, field)
		}
	}
	topUp, err := schema.Parse(&CreditTopUp{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	if topUp.FieldsByDBName["amount_minor"] == nil || !topUp.FieldsByDBName["amount_minor"].NotNull || topUp.FieldsByDBName["gateway_reference"] == nil {
		t.Fatalf("unsafe credit top-up metadata: %#v", topUp.FieldsByDBName)
	}
	transaction, err := schema.Parse(&CreditTransaction{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	if field := transaction.FieldsByDBName["deduplication_key"]; field == nil || !field.NotNull || field.TagSettings["UNIQUEINDEX"] == "" {
		t.Fatalf("credit ledger lacks unique deduplication key: %#v", field)
	}
}

func TestCreditArithmeticRejectsOverflow(t *testing.T) {
	if _, err := addCredit(math.MaxInt64, 1); !errors.Is(err, ErrInvalidCredit) {
		t.Fatalf("positive overflow error=%v", err)
	}
	if _, err := addCredit(math.MinInt64, -1); !errors.Is(err, ErrInvalidCredit) {
		t.Fatalf("negative overflow error=%v", err)
	}
	if got, err := addCredit(-5, 10); err != nil || got != 5 {
		t.Fatalf("balance=%d err=%v", got, err)
	}
}

func TestCreditPaymentMustMatchServerReservation(t *testing.T) {
	topUp := CreditTopUp{ID: "topup-1", Gateway: BillingGatewayStripe, AmountMinor: 2500, Currency: "USD"}
	payment := CreditPayment{TopUpID: topUp.ID, Gateway: topUp.Gateway, GatewayPaymentID: "pi_1", AmountMinor: topUp.AmountMinor, Currency: "usd"}
	if !creditPaymentMatches(topUp, payment) {
		t.Fatal("matching verified payment was rejected")
	}
	for _, changed := range []CreditPayment{
		{TopUpID: "topup-2", Gateway: payment.Gateway, GatewayPaymentID: payment.GatewayPaymentID, AmountMinor: payment.AmountMinor, Currency: payment.Currency},
		{TopUpID: payment.TopUpID, Gateway: BillingGatewayPayPal, GatewayPaymentID: payment.GatewayPaymentID, AmountMinor: payment.AmountMinor, Currency: payment.Currency},
		{TopUpID: payment.TopUpID, Gateway: payment.Gateway, GatewayPaymentID: payment.GatewayPaymentID, AmountMinor: 2400, Currency: payment.Currency},
		{TopUpID: payment.TopUpID, Gateway: payment.Gateway, GatewayPaymentID: payment.GatewayPaymentID, AmountMinor: payment.AmountMinor, Currency: "EUR"},
		{TopUpID: payment.TopUpID, Gateway: payment.Gateway, AmountMinor: payment.AmountMinor, Currency: payment.Currency},
	} {
		if creditPaymentMatches(topUp, changed) {
			t.Fatalf("mismatched payment was accepted: %#v", changed)
		}
	}
}

func TestApplicationSettingsMigrationMetadata(t *testing.T) {
	parsed, err := schema.Parse(&ApplicationSetting{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.FieldsByDBName["key"] == nil || !parsed.FieldsByDBName["key"].PrimaryKey {
		t.Fatal("application setting key is not a primary key")
	}
	for _, name := range []string{"value", "updated_by"} {
		if parsed.FieldsByDBName[name] == nil || !parsed.FieldsByDBName[name].NotNull {
			t.Fatalf("application setting %s is nullable", name)
		}
	}
}

func TestPostgresConfigPreservesTimeZoneAndCredentials(t *testing.T) {
	cfg := &config.DatabaseConfig{
		Host: "db.example", Port: 5432, User: "objectshare",
		Password: "slash/colon:at@percent%", Database: "objectshare",
		SSLMode: "require", TimeZone: "Asia/Taipei",
		ConnMaxLifetime: config.Duration(30 * time.Minute),
	}
	parsed, location, err := postgresConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.RuntimeParams["timezone"]; got != cfg.TimeZone {
		t.Fatalf("runtime timezone = %q, want %q", got, cfg.TimeZone)
	}
	if location.String() != cfg.TimeZone {
		t.Fatalf("scan timezone = %q, want %q", location, cfg.TimeZone)
	}
	if parsed.Password != cfg.Password {
		t.Fatal("database password was changed while parsing the connection configuration")
	}
}

func TestPostgresConfigRejectsUnknownTimeZone(t *testing.T) {
	cfg := &config.DatabaseConfig{
		Host: "localhost", Port: 5432, User: "objectshare", Database: "objectshare",
		SSLMode: "disable", TimeZone: "Not/A_Real_Zone",
	}
	if _, _, err := postgresConfig(cfg); err == nil {
		t.Fatal("expected an invalid timezone error")
	}
}

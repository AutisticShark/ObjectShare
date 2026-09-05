package htmx

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/go-chi/chi/v5"
)

type entitlementRepository struct {
	*memoryRepository
	entitlements  db.Entitlements
	plan          *db.PaidPlan
	applied       *db.SubscriptionUpdate
	topUp         *db.CreditTopUp
	creditPayment *db.CreditPayment
	transactions  []db.CreditTransaction
	purchaseErr   error
	adjustment    *creditAdjustment
}

type creditAdjustment struct {
	UserID, Description, AdministratorID string
	Delta                                int64
}

func (repo *entitlementRepository) PublicPlans(context.Context) ([]db.PaidPlan, error) {
	if repo.plan != nil {
		return []db.PaidPlan{*repo.plan}, nil
	}
	return nil, nil
}
func (repo *entitlementRepository) AllPlans(context.Context) ([]db.PaidPlan, error) { return nil, nil }
func (repo *entitlementRepository) PlanByID(_ context.Context, id string, _ bool) (*db.PaidPlan, error) {
	if repo.plan == nil || repo.plan.ID != id {
		return nil, db.ErrNotFound
	}
	return repo.plan, nil
}
func (repo *entitlementRepository) PlanByGatewayID(context.Context, string, string) (*db.PaidPlan, error) {
	if repo.plan == nil {
		return nil, db.ErrNotFound
	}
	return repo.plan, nil
}
func (repo *entitlementRepository) CreatePlan(context.Context, *db.PaidPlan) error { return nil }
func (repo *entitlementRepository) UpdatePlan(context.Context, *db.PaidPlan) error { return nil }
func (repo *entitlementRepository) Entitlements(context.Context, string, time.Time) (db.Entitlements, error) {
	return repo.entitlements, nil
}
func (repo *entitlementRepository) SubscriptionForUser(context.Context, string) (*db.Subscription, error) {
	return nil, db.ErrNotFound
}
func (repo *entitlementRepository) ReserveBillingCheckout(context.Context, string, string, time.Time) error {
	return nil
}
func (repo *entitlementRepository) ReleaseBillingCheckout(context.Context, string, string) error {
	return nil
}
func (repo *entitlementRepository) ApplySubscription(_ context.Context, update db.SubscriptionUpdate) (bool, error) {
	repo.applied = &update
	return true, nil
}
func (repo *entitlementRepository) CreateCreditTopUp(_ context.Context, topUp *db.CreditTopUp) error {
	copy := *topUp
	repo.topUp = &copy
	return nil
}
func (repo *entitlementRepository) BindCreditTopUp(_ context.Context, id, gateway, reference string) error {
	if repo.topUp == nil || repo.topUp.ID != id || repo.topUp.Gateway != gateway {
		return db.ErrNotFound
	}
	repo.topUp.GatewayReference = &reference
	return nil
}
func (repo *entitlementRepository) CancelCreditTopUp(context.Context, string, string) error {
	return nil
}
func (repo *entitlementRepository) CreditTopUpByID(_ context.Context, id string) (*db.CreditTopUp, error) {
	if repo.topUp == nil || repo.topUp.ID != id {
		return nil, db.ErrNotFound
	}
	copy := *repo.topUp
	return &copy, nil
}
func (repo *entitlementRepository) ApplyCreditTopUp(_ context.Context, payment db.CreditPayment, _ time.Time) (bool, error) {
	repo.creditPayment = &payment
	return true, nil
}
func (repo *entitlementRepository) CreditTransactions(context.Context, string, int) ([]db.CreditTransaction, error) {
	return repo.transactions, nil
}
func (repo *entitlementRepository) PurchasePlanWithCredit(context.Context, string, string, string, time.Time) (*db.Subscription, error) {
	return &db.Subscription{}, repo.purchaseErr
}
func (repo *entitlementRepository) AdjustCredit(_ context.Context, userID string, delta int64, description, administratorID, _ string, _ time.Time) (int64, error) {
	repo.adjustment = &creditAdjustment{UserID: userID, Delta: delta, Description: description, AdministratorID: administratorID}
	return delta, nil
}

type checkoutGatewayStub struct {
	topUpInput *billingTopUpInput
}

func (stub *checkoutGatewayStub) TopUp(_ context.Context, input billingTopUpInput) (billingTopUpResult, error) {
	stub.topUpInput = &input
	return billingTopUpResult{Location: "https://www.sandbox.paypal.com/approve"}, nil
}
func (*checkoutGatewayStub) Portal(context.Context, *db.Subscription, string) (string, error) {
	return "https://www.sandbox.paypal.com/myaccount/autopay/connect/", nil
}

func TestDirectDownloadRequiresActivePlanEntitlement(t *testing.T) {
	owner := "11111111-1111-4111-8111-111111111111"
	fileID := "22222222-2222-4222-8222-222222222222"
	repository := &entitlementRepository{memoryRepository: &memoryRepository{files: map[string]*db.FileList{
		fileID: {FileID: fileID, FileOwner: &owner, FileName: "report.txt", FileSize: 4, ContentType: "text/plain", UploadStatus: "complete"},
	}}}
	storage := &memoryStorage{objects: map[string][]byte{fileID: []byte("data")}}
	handler := newTestHandler(t, repository, storage)
	router := chi.NewRouter()
	router.Get("/api/v1/download/{id}", handler.Download)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/download/"+fileID, nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/file/"+fileID {
		t.Fatalf("inactive direct download status=%d location=%q", response.Code, response.Header().Get("Location"))
	}

	repository.entitlements = db.Entitlements{Active: true, DirectLinks: true}
	response = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/api/v1/download/"+fileID, nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "data" {
		t.Fatalf("active direct download status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestDetailsPageDownloadTokenIsBoundAndExpires(t *testing.T) {
	handler := newTestHandler(t, &entitlementRepository{memoryRepository: &memoryRepository{files: map[string]*db.FileList{}}}, &memoryStorage{objects: map[string][]byte{}})
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	token := handler.downloadFormToken("file-a", now.Add(10*time.Minute))
	if !handler.validDownloadFormToken("file-a", token, now) {
		t.Fatal("fresh token was rejected")
	}
	if handler.validDownloadFormToken("file-b", token, now) {
		t.Fatal("token was accepted for another file")
	}
	if handler.validDownloadFormToken("file-a", token, now.Add(11*time.Minute)) {
		t.Fatal("expired token was accepted")
	}
}

func TestExternalPlanCheckoutIsRetired(t *testing.T) {
	handler := newTestHandler(t, &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}}, &memoryStorage{objects: make(map[string][]byte)})
	for _, gateway := range []string{db.BillingGatewayStripe, db.BillingGatewayPayPal} {
		handler.billingGateways = map[string]billingGateway{gateway: &checkoutGatewayStub{}}
		response := httptest.NewRecorder()
		handler.BillingCheckout(response, httptest.NewRequest(http.MethodPost, "/billing/checkout/plan", nil))
		if response.Code != http.StatusGone || response.Header().Get("Location") != "" {
			t.Fatalf("status=%d location=%q", response.Code, response.Header().Get("Location"))
		}
	}
}

func TestBillingTopUpUsesAuthenticatedAccountAndConfiguredValue(t *testing.T) {
	user := &db.User{ID: "11111111-1111-4111-8111-111111111111", Email: "user@example.com"}
	repository := &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}}
	handler := newTestHandler(t, repository, &memoryStorage{objects: make(map[string][]byte)})
	handler.config.Billing = &config.BillingConfig{PublicURL: "https://share.example.com", CreditCurrency: "USD", MinTopUpCredits: 5, MaxTopUpCredits: 1000}
	gateway := &checkoutGatewayStub{}
	handler.billingGateways = map[string]billingGateway{db.BillingGatewayStripe: gateway}
	router := chi.NewRouter()
	router.Post("/{gateway}", handler.BillingTopUp)
	request := httptest.NewRequest(http.MethodPost, "/stripe", strings.NewReader(url.Values{"credits": {"25"}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: user, Transport: transportBearer}))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || repository.topUp == nil || gateway.topUpInput == nil {
		t.Fatalf("status=%d topup=%#v input=%#v body=%q", response.Code, repository.topUp, gateway.topUpInput, response.Body.String())
	}
	if repository.topUp.UserID != user.ID || repository.topUp.Credits != 25 || repository.topUp.AmountMinor != 2500 || repository.topUp.Currency != "USD" {
		t.Fatalf("reserved top-up=%#v", repository.topUp)
	}
	if gateway.topUpInput.TopUpID != repository.topUp.ID || gateway.topUpInput.UserID != user.ID || gateway.topUpInput.Email != user.Email || gateway.topUpInput.AmountMinor != 2500 {
		t.Fatalf("gateway top-up input=%#v", gateway.topUpInput)
	}

	request = httptest.NewRequest(http.MethodPost, "/stripe", strings.NewReader(url.Values{"credits": {"4"}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: user, Transport: transportBearer}))
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("below-minimum top-up status=%d body=%q", response.Code, response.Body.String())
	}

	repository.topUp, gateway.topUpInput = nil, nil
	request = httptest.NewRequest(http.MethodPost, "/stripe", strings.NewReader(url.Values{"credits": {"25"}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: user, Transport: transportCookie, Claims: &appauth.Claims{CSRF: "expected"}}))
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || repository.topUp != nil || gateway.topUpInput != nil {
		t.Fatalf("missing CSRF status=%d topup=%#v input=%#v", response.Code, repository.topUp, gateway.topUpInput)
	}
}

func TestCreditPlanPurchaseReportsInsufficientBalance(t *testing.T) {
	user := &db.User{ID: "11111111-1111-4111-8111-111111111111"}
	repository := &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}, purchaseErr: db.ErrInsufficientCredit}
	handler := newTestHandler(t, repository, &memoryStorage{objects: make(map[string][]byte)})
	router := chi.NewRouter()
	router.Post("/{id}", handler.BillingPurchaseWithCredit)
	request := httptest.NewRequest(http.MethodPost, "/22222222-2222-4222-8222-222222222222", strings.NewReader("credit_request_id=33333333-3333-4333-8333-333333333333"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: user, Transport: transportBearer}))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusPaymentRequired {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestAdminCreditAdjustmentIsCSRFProtectedAndAudited(t *testing.T) {
	admin := &db.User{ID: "11111111-1111-4111-8111-111111111111", Role: db.RoleAdmin}
	targetID := "22222222-2222-4222-8222-222222222222"
	repository := &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}}
	handler := newTestHandler(t, repository, &memoryStorage{objects: make(map[string][]byte)})
	router := chi.NewRouter()
	router.With(handler.RequireAdmin).Post("/{id}", handler.AdminAdjustCredit)
	values := url.Values{"credit_delta": {"-7"}, "credit_description": {"Refund correction"}, "csrf_token": {"expected"}, "credit_request_id": {"33333333-3333-4333-8333-333333333333"}}
	request := httptest.NewRequest(http.MethodPost, "/"+targetID, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: admin, Transport: transportCookie, Claims: &appauth.Claims{CSRF: "expected"}}))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || repository.adjustment == nil || repository.adjustment.UserID != targetID || repository.adjustment.Delta != -7 || repository.adjustment.AdministratorID != admin.ID || repository.adjustment.Description != "Refund correction" {
		t.Fatalf("status=%d adjustment=%#v body=%q", response.Code, repository.adjustment, response.Body.String())
	}

	repository.adjustment = nil
	values.Del("csrf_token")
	request = httptest.NewRequest(http.MethodPost, "/"+targetID, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: admin, Transport: transportCookie, Claims: &appauth.Claims{CSRF: "expected"}}))
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || repository.adjustment != nil {
		t.Fatalf("missing CSRF status=%d adjustment=%#v", response.Code, repository.adjustment)
	}

	values.Set("csrf_token", "expected")
	request = httptest.NewRequest(http.MethodPost, "/"+targetID, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: &db.User{ID: targetID, Role: db.RoleUser}, Transport: transportBearer}))
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || repository.adjustment != nil {
		t.Fatalf("non-admin status=%d adjustment=%#v", response.Code, repository.adjustment)
	}
}

func TestProxiedMultipleFileUploadStoresEveryFile(t *testing.T) {
	repository := &memoryRepository{files: make(map[string]*db.FileList)}
	storage := &memoryStorage{objects: make(map[string][]byte)}
	handler := newTestHandler(t, repository, storage)
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	for _, item := range []struct{ name, body string }{{"one.txt", "one"}, {"two.txt", "two"}} {
		part, err := form.CreateFormFile("file", item.name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = part.Write([]byte(item.body))
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/upload", &body)
	request.Header.Set("Content-Type", form.FormDataContentType())
	response := httptest.NewRecorder()
	handler.Upload(response, request)
	if response.Code != http.StatusSeeOther || !strings.HasPrefix(response.Header().Get("Location"), "/uploads/complete?ids=") {
		t.Fatalf("status=%d location=%q body=%q", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	if len(repository.files) != 2 || len(storage.objects) != 2 {
		t.Fatalf("files=%d objects=%d", len(repository.files), len(storage.objects))
	}
}

func TestDirectBatchAuthorizesEveryFileWithOneRequest(t *testing.T) {
	repository := &memoryRepository{files: make(map[string]*db.FileList)}
	handler := newTestHandler(t, repository, &directMemoryStorage{memoryStorage: &memoryStorage{objects: make(map[string][]byte)}})
	body := strings.NewReader(`{"files":[{"file_name":"one.txt","file_size":3,"content_type":"text/plain"},{"file_name":"two.txt","file_size":3,"content_type":"text/plain"}]}`)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/uploads/direct/batch", body)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.BeginDirectUploadBatch(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	var result struct {
		Uploads []directUploadAuthorization `json:"uploads"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Uploads) != 2 || len(repository.files) != 2 {
		t.Fatalf("authorizations=%d records=%d", len(result.Uploads), len(repository.files))
	}
	for _, authorization := range result.Uploads {
		if authorization.UploadURL == "" || authorization.Token == "" || authorization.CompleteURL == "" {
			t.Fatalf("incomplete authorization: %#v", authorization)
		}
	}
}

func TestLocalPlanFormUsesOnePriceWithoutGateway(t *testing.T) {
	values := url.Values{"name": {"Plus"}, "price": {"10"}, "duration_days": {"30"}, "storage_quota_gib": {"10"}, "retention_days": {"30"}, "sort_order": {"0"}}
	parse := func() (*db.PaidPlan, error) {
		request := httptest.NewRequest(http.MethodPost, "/admin/plans", strings.NewReader(values.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return paidPlanFromForm(request)
	}
	plan, err := parse()
	if err != nil || plan.Price != 10 || plan.DurationDays != 30 || plan.Gateway != "" || plan.GatewayPlanID != "" {
		t.Fatalf("plan=%#v err=%v", plan, err)
	}
	// Old or forged provider and alternate-price fields cannot alter the local offer.
	values.Set("gateway", "stripe")
	values.Set("gateway_plan_id", "price_attacker")
	values.Set("price_label", "$1/month")
	values.Set("credit_price", "1")
	plan, err = parse()
	if err != nil || plan.Price != 10 || plan.Gateway != "" || plan.GatewayPlanID != "" || plan.LegacyPriceLabel != "" {
		t.Fatalf("plan=%#v err=%v", plan, err)
	}
	for field, invalid := range map[string][]string{"price": {"", "0", "-1", "1.5", "1000000001", "9223372036854775808"}, "duration_days": {"", "0", "-1", "36501"}, "storage_quota_gib": {"NaN", "+Inf", "0.001"}} {
		original := values.Get(field)
		for _, value := range invalid {
			values.Set(field, value)
			if _, err := parse(); err == nil {
				t.Errorf("accepted %s=%q", field, value)
			}
		}
		values.Set(field, original)
	}
}

func TestPlansDisplayStoredPriceWithoutConfiguredGateway(t *testing.T) {
	repo := &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}, plan: &db.PaidPlan{ID: "plan", Name: "Plus", LegacyPriceLabel: "$999 / month", Price: 10, DurationDays: 30, StorageQuotaBytes: 1024}}
	handler := newTestHandler(t, repo, &memoryStorage{objects: make(map[string][]byte)})
	handler.billingGateways = nil
	var err error
	handler.templates, err = parseTemplates(os.DirFS("../.."), config.BrandingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/plans", nil)
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: &db.User{ID: "user"}, Claims: &appauth.Claims{CSRF: "csrf"}, Transport: transportBearer}))
	response := httptest.NewRecorder()
	handler.Plans(response, request)
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, "10 credits") || !strings.Contains(body, "30 days") || !strings.Contains(body, `action="/billing/credit/plan"`) {
		t.Fatalf("status=%d body=%s", response.Code, body)
	}
	for _, forbidden := range []string{"$999", "/billing/checkout/", "Subscribe with", "No plans are currently available"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("unexpected %q", forbidden)
		}
	}
	repo.plan.Price = 0
	response = httptest.NewRecorder()
	handler.Plans(response, request)
	if strings.Contains(response.Body.String(), `action="/billing/credit/plan"`) {
		t.Fatal("offered a legacy plan without a numeric price")
	}
}

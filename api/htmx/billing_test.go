package htmx

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/go-chi/chi/v5"
)

type entitlementRepository struct {
	*memoryRepository
	entitlements db.Entitlements
	plan         *db.PaidPlan
	applied      *db.SubscriptionUpdate
}

func (repo *entitlementRepository) PublicPlans(context.Context) ([]db.PaidPlan, error) {
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

type checkoutGatewayStub struct{ input *billingCheckoutInput }

func (stub *checkoutGatewayStub) Checkout(_ context.Context, input billingCheckoutInput) (string, error) {
	stub.input = &input
	return "https://www.sandbox.paypal.com/approve", nil
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

func TestBillingCheckoutDispatchesTrustedPlanToConfiguredGateway(t *testing.T) {
	user := &db.User{ID: "11111111-1111-4111-8111-111111111111", Email: "user@example.com"}
	plan := &db.PaidPlan{ID: "22222222-2222-4222-8222-222222222222", Gateway: db.BillingGatewayPayPal, GatewayPlanID: "P-ABCDEFGHIJKLMNOPQRSTUVWX", Active: true}
	repository := &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}, plan: plan}
	handler := newTestHandler(t, repository, &memoryStorage{objects: make(map[string][]byte)})
	handler.config.Billing = &config.BillingConfig{PublicURL: "https://share.example.com"}
	gateway := &checkoutGatewayStub{}
	handler.billingGateways = map[string]billingGateway{db.BillingGatewayPayPal: gateway}
	router := chi.NewRouter()
	router.Post("/{id}", handler.BillingCheckout)
	request := httptest.NewRequest(http.MethodPost, "/"+plan.ID, nil)
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: user, Transport: transportBearer}))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "https://www.sandbox.paypal.com/approve" {
		t.Fatalf("status=%d location=%q body=%q", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	if gateway.input == nil || gateway.input.GatewayPlanID != plan.GatewayPlanID || gateway.input.UserID != user.ID || gateway.input.SuccessURL != "https://share.example.com/account?message=billing-pending" {
		t.Fatalf("checkout input=%#v", gateway.input)
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

func TestPaidPlanFormRejectsUntrustedPriceIDs(t *testing.T) {
	values := url.Values{"name": {"Plus"}, "gateway": {"stripe"}, "gateway_plan_id": {"product_not_a_price"}, "price_label": {"$5/month"}, "storage_quota_gib": {"10"}, "retention_days": {"30"}, "sort_order": {"0"}}
	request := httptest.NewRequest(http.MethodPost, "/admin/plans", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = request.ParseForm()
	if _, err := paidPlanFromForm(request); err == nil {
		t.Fatal("non-Price Stripe identifier was accepted")
	}
	values.Set("gateway", "paypal")
	values.Set("gateway_plan_id", "price_not_a_paypal_plan")
	request = httptest.NewRequest(http.MethodPost, "/admin/plans", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = request.ParseForm()
	if _, err := paidPlanFromForm(request); err == nil {
		t.Fatal("invalid PayPal plan identifier was accepted")
	}
}

package htmx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/go-chi/chi/v5"
)

func (repo *authMemoryRepository) ReserveEmailVerification(_ context.Context, id, address, hash string, now, expires time.Time) (bool, error) {
	user := repo.users[id]
	if user == nil || !user.Active || user.Email != address || user.EmailVerifiedAt != nil || (user.EmailVerificationSentAt != nil && user.EmailVerificationSentAt.After(now.Add(-time.Minute))) {
		return false, nil
	}
	user.EmailVerificationHash, user.EmailVerificationSentAt, user.EmailVerificationExpiresAt = hash, &now, &expires
	return true, nil
}

func (repo *authMemoryRepository) VerifyEmail(_ context.Context, id, hash string, now time.Time) (bool, error) {
	user := repo.users[id]
	if user == nil || !user.Active || user.EmailVerifiedAt != nil || hash == "" || user.EmailVerificationHash != hash || user.EmailVerificationExpiresAt == nil || !user.EmailVerificationExpiresAt.After(now) {
		return false, nil
	}
	user.EmailVerifiedAt, user.EmailVerificationExpiresAt, user.EmailVerificationHash = &now, nil, ""
	return true, nil
}

func verificationIdentity(request *http.Request, user *db.User) *http.Request {
	return request.WithContext(context.WithValue(request.Context(), identityContextKey{}, &identity{User: user, Claims: &appauth.Claims{CSRF: "expected"}, Transport: transportBearer}))
}

func TestSignupVerificationDeliveryConfirmationAndReplay(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "accepted", true: "ambiguous"}[failed], func(t *testing.T) {
			repo := newAuthMemoryRepository()
			h := newAuthTestHandler(t, repo, false)
			h.config.Auth.EmailVerification.PublicURL = "https://files.example.com"
			h.config.Email = &config.EmailConfig{Provider: "smtp"}
			sender := &fakeEmailSender{}
			if failed {
				sender.err = errors.New("ambiguous provider failure")
			}
			h.emailSender = sender
			page := httptest.NewRecorder()
			h.SignupPage(page, httptest.NewRequest("GET", "/signup", nil))
			request := formRequest("/signup", url.Values{"csrf_token": {page.Body.String()}, "email": {"verify@example.com"}, "display_name": {"Verify User"}, "password": {"a sufficiently long password"}, "password_confirm": {"a sufficiently long password"}})
			request.Host = "attacker.example"
			request.AddCookie(page.Result().Cookies()[0])
			response := httptest.NewRecorder()
			h.Signup(response, request)
			if response.Code != 303 || len(sender.messages) != 1 {
				t.Fatalf("signup: %d emails=%d", response.Code, len(sender.messages))
			}
			user, err := repo.UserByEmail(t.Context(), "verify@example.com")
			if err != nil || user.EmailVerifiedAt != nil {
				t.Fatal("signup prematurely verified account", err)
			}
			user = repo.users[user.ID]
			message := sender.messages[0]
			link := regexp.MustCompile(`https://files\.example\.com/verify-email\?[^\s]+`).FindString(message.Text)
			u, err := url.Parse(link)
			if err != nil || link == "" || message.To != user.Email || strings.Contains(message.Text, "attacker.example") {
				t.Fatal("invalid verification email")
			}
			token := u.Query().Get("token")
			if user.EmailVerificationHash != appauth.TokenHash(token) || strings.Contains(response.Body.String(), token) {
				t.Fatal("token stored or exposed incorrectly")
			}
			if _, err := h.jwt.Parse(token); err == nil {
				t.Fatal("verification token accepted as JWT")
			}
			if failed && !strings.Contains(response.Header().Get("Location"), "verification-failed") {
				t.Fatal("delivery failure hidden")
			}
			if err := h.sendVerification(t.Context(), user); !errors.Is(err, errVerificationCooldown) || len(sender.messages) != 1 {
				t.Fatal("immediate retry sent another email", err)
			}
			h.templates, err = parseTemplates(os.DirFS("../.."), config.BrandingConfig{})
			if err != nil {
				t.Fatal(err)
			}
			page = httptest.NewRecorder()
			h.VerifyEmailPage(page, httptest.NewRequest("GET", link, nil))
			if user.EmailVerifiedAt != nil || !strings.Contains(page.Header().Get("Cache-Control"), "no-store") {
				t.Fatal("GET consumed or cached verification")
			}
			csrf := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(page.Body.String())
			if len(csrf) != 2 {
				t.Fatal("verification form missing CSRF")
			}
			// Complete on a separately initialized replica sharing the JWT key.
			other := newAuthTestHandler(t, repo, false)
			other.templates = h.templates
			for _, validCSRF := range []bool{false, true, true} {
				values := url.Values{"user": {user.ID}, "token": {token}}
				if validCSRF {
					values.Set("csrf_token", csrf[1])
				}
				post := formRequest("/verify-email", values)
				post.AddCookie(page.Result().Cookies()[0])
				wasVerified := user.EmailVerifiedAt != nil
				result := httptest.NewRecorder()
				other.VerifyEmail(result, post)
				want := 200
				if !validCSRF {
					want = 403
				} else if wasVerified {
					want = 400
				}
				if result.Code != want {
					t.Fatalf("confirmation status=%d want=%d body=%s", result.Code, want, result.Body.String())
				}
				if len(result.Result().Cookies()) != 0 {
					t.Fatal("verification issued authentication cookie")
				}
			}
		})
	}
}

func TestEmailVerificationPolicyMatrixAndUploadRoutes(t *testing.T) {
	for _, role := range []string{db.RoleUser, db.RoleAdmin} {
		for _, verified := range []bool{false, true} {
			for _, purchases := range []bool{false, true} {
				for _, uploads := range []bool{false, true} {
					h := newAuthTestHandler(t, newAuthMemoryRepository(), false)
					h.config.Auth.EmailVerification = config.EmailVerificationConfig{RequireForPurchases: purchases, RequireForUploads: uploads}
					user := &db.User{Role: role, Active: true}
					if verified {
						now := time.Now()
						user.EmailVerifiedAt = &now
					}
					r := verificationIdentity(httptest.NewRequest("POST", "/", nil), user)
					if got := h.purchaseAllowed(httptest.NewRecorder(), r); got != (!purchases || verified) {
						t.Fatal("purchase policy matrix")
					}
					if got := h.uploadAllowed(httptest.NewRecorder(), r); got != (!uploads || verified) {
						t.Fatal("upload policy matrix")
					}
				}
			}
		}
	}
	repo := newAuthMemoryRepository()
	h := newAuthTestHandler(t, repo, false)
	h.config.Auth.EmailVerification.RequireForUploads = true
	h.config.Upload = &config.UploadConfig{GuestEnabled: true}
	h.direct = &directMemoryStorage{memoryStorage: &memoryStorage{objects: make(map[string][]byte)}}
	user := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Active: true}
	repo.users[user.ID] = user
	for _, call := range []http.HandlerFunc{h.Upload, h.BeginDirectUpload, h.BeginDirectUploadBatch} {
		r := verificationIdentity(httptest.NewRequest("POST", "/", strings.NewReader("invalid body")), user)
		w := httptest.NewRecorder()
		call(w, r)
		if w.Code != 403 || len(repo.files) != 0 {
			t.Fatalf("upload route not gated: %d %s", w.Code, w.Body.String())
		}
	}
	if !h.uploadAllowed(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil)) {
		t.Fatal("guest setting changed")
	}
	id := "9dcaa8d1-3a21-4261-9c72-a25d437f58cb"
	expires := time.Now().Add(time.Hour)
	file := &db.FileList{FileID: id, FileOwner: &user.ID, UploadStatus: "pending", AnonymousSessionToken: appauth.TokenHash("owner-token"), UploadExpiresAt: &expires}
	repo.files[id] = file
	router := chi.NewRouter()
	router.Post("/uploads/{id}/complete", h.CompleteDirectUpload)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/uploads/"+id+"/complete", strings.NewReader(`{"token":"owner-token"}`)))
	if w.Code != 403 || file.UploadStatus != "pending" {
		t.Fatalf("owner-token bypass: %d %s", w.Code, w.Body.String())
	}
	now := time.Now()
	user.EmailVerifiedAt = &now
	if !h.directUploadVerificationAllowed(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil), file) {
		t.Fatal("verified owner rejected")
	}
}

func TestUnverifiedInvoiceCreationAndPaymentRejected(t *testing.T) {
	owner, id := "60c628c1-85cb-4463-b895-a629c31bfa55", "9dcaa8d1-3a21-4261-9c72-a25d437f58cb"
	repo := &invoiceTestRepository{entitlementRepository: &entitlementRepository{memoryRepository: &memoryRepository{files: make(map[string]*db.FileList)}}, invoice: db.Invoice{ID: id, UserID: owner, Kind: "plan"}}
	h := newTestHandler(t, repo, &memoryStorage{objects: make(map[string][]byte)})
	h.config.Auth = &config.AuthConfig{EmailVerification: config.EmailVerificationConfig{RequireForPurchases: true}}
	user := &db.User{ID: owner, Active: true}
	router := chi.NewRouter()
	router.Post("/create/{id}", h.CreateInvoice)
	router.Post("/credit/{id}", h.BillingPurchaseWithCredit)
	router.Post("/pay/{id}", h.PayInvoice)
	for _, path := range []string{"/create/", "/credit/", "/pay/"} {
		for _, gateway := range []string{"credit", "stripe", "paypal"} {
			w := httptest.NewRecorder()
			router.ServeHTTP(w, verificationIdentity(formRequest(path+id, url.Values{"gateway": {gateway}}), user))
			if w.Code != 403 || repo.created || repo.paid {
				t.Fatalf("unverified purchase %s %s: %d", path, gateway, w.Code)
			}
		}
	}
}

func TestVerificationSettingsFormSwitchesAndOlderClients(t *testing.T) {
	runtime := config.RuntimeConfig{Auth: config.RuntimeAuthConfig{EmailVerification: config.EmailVerificationConfig{PublicURL: "https://files.example.com", RequireForPurchases: true, RequireForUploads: true}}}
	want := runtime.Auth.EmailVerification
	r := formRequest("/admin/settings", url.Values{})
	_ = r.ParseForm()
	_ = updateRuntimeFromForm(&runtime, r)
	if runtime.Auth.EmailVerification != want {
		t.Fatal("older form erased verification settings")
	}
	for _, purchases := range []bool{false, true} {
		for _, uploads := range []bool{false, true} {
			values := url.Values{"verification_public_url": {"https://new.example.com"}}
			if purchases {
				values.Set("verification_require_for_purchases", "on")
			}
			if uploads {
				values.Set("verification_require_for_uploads", "on")
			}
			r = formRequest("/admin/settings", values)
			_ = r.ParseForm()
			_ = updateRuntimeFromForm(&runtime, r)
			if c := runtime.Auth.EmailVerification; c.PublicURL != "https://new.example.com" || c.RequireForPurchases != purchases || c.RequireForUploads != uploads {
				t.Fatal("verification form lost independent switches")
			}
		}
	}
}

func TestVerificationResendCSRFAndProfileChange(t *testing.T) {
	repo := newAuthMemoryRepository()
	h := newAuthTestHandler(t, repo, false)
	h.config.Email = &config.EmailConfig{Provider: "smtp"}
	h.config.Auth.EmailVerification.PublicURL = "https://files.example.com"
	sender := &fakeEmailSender{}
	h.emailSender = sender
	now := time.Now().UTC()
	user := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "old@example.com", DisplayName: "User", Active: true, Role: db.RoleUser, TokenVersion: 1, EmailVerifiedAt: &now}
	repo.users[user.ID] = user
	token, claims := issueTestJWT(t, h, user)
	// A real JWT remains valid after verification state changes; authorization
	// reloads the user, so the change does not depend on stale JWT claims.
	profile := formRequest("/account/profile", url.Values{"email": {"new@example.com"}, "display_name": {"User"}, "csrf_token": {claims.CSRF}})
	profile.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.Authenticate(http.HandlerFunc(h.UpdateProfile)).ServeHTTP(w, profile)
	if w.Code != 303 || user.EmailVerifiedAt != nil || len(sender.messages) != 1 || sender.messages[0].To != "new@example.com" {
		t.Fatalf("profile reverification: %d emails=%d", w.Code, len(sender.messages))
	}
	for _, csrf := range []string{"", claims.CSRF} {
		request := formRequest("/account/email/resend", url.Values{"csrf_token": {csrf}, "email": {"attacker@example.com"}})
		request.AddCookie(&http.Cookie{Name: h.jwtCookieName(), Value: token})
		w = httptest.NewRecorder()
		h.Authenticate(http.HandlerFunc(h.ResendVerification)).ServeHTTP(w, request)
		want := 403
		if csrf != "" {
			want = 303
		}
		if w.Code != want || len(sender.messages) != 1 {
			t.Fatalf("resend CSRF/cooldown: %d", w.Code)
		}
	}
	user.EmailVerificationSentAt = nil
	request := formRequest("/account/email/resend", url.Values{"email": {"attacker@example.com"}})
	request.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	h.Authenticate(http.HandlerFunc(h.ResendVerification)).ServeHTTP(w, request)
	if w.Code != 303 || len(sender.messages) != 2 || sender.messages[1].To != "new@example.com" {
		t.Fatal("resend recipient controlled by request")
	}
	h.config.Auth.EmailVerification.RequireForUploads = true
	check := func(want bool) {
		t.Helper()
		request := httptest.NewRequest("POST", "/", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		h.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := h.uploadAllowed(w, r); got != want {
				t.Fatalf("JWT used stale verification: %v", got)
			}
		})).ServeHTTP(httptest.NewRecorder(), request)
	}
	check(false)
	user.EmailVerifiedAt = &now
	check(true)
}

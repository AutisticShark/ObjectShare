package htmx

import (
	"context"
	"encoding/json"
	"errors"
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
)

func (repository *authMemoryRepository) MutateMFA(_ context.Context, id string, version int, mutate func(*db.User) error) (*db.User, error) {
	stored := repository.users[id]
	if stored == nil || !stored.CanAuthenticate() || stored.TokenVersion != version {
		return nil, db.ErrConflict
	}
	copy := *stored
	copy.MFA.Recovery = append([]string(nil), stored.MFA.Recovery...)
	if err := mutate(&copy); err != nil {
		return nil, err
	}
	stored.MFA, stored.TokenVersion = copy.MFA, copy.TokenVersion
	return &copy, nil
}

func mfaFixture(t *testing.T, method string) (*Handler, *authMemoryRepository, *db.User, string) {
	t.Helper()
	repo := newAuthMemoryRepository()
	user := &db.User{ID: "11111111-1111-4111-8111-111111111111", Email: "mfa@example.com", DisplayName: "MFA User", Role: db.RoleUser, Active: true, TokenVersion: 1}
	now := time.Now()
	user.EmailVerifiedAt = &now
	user.PasswordHash, _ = appauth.HashPassword("a sufficiently long password")
	if err := repo.CreateUser(t.Context(), user); err != nil {
		t.Fatal(err)
	}
	h := newAuthTestHandler(t, repo, false)
	var err error
	h.templates, err = parseTemplates(os.DirFS("../.."), h.config.Branding)
	if err != nil {
		t.Fatal(err)
	}
	user = repo.users[user.ID]
	secret, _ := appauth.NewTOTPSecret()
	user.MFA.Method = method
	user.MFA.Secret, _ = appauth.SealMFASecret(h.settingsKey, user.ID, secret)
	user.MFA.Recovery = []string{appauth.MFAHash(h.settingsKey, user.ID+":recovery", strings.Repeat("a", 32))}
	h.config.Email = &config.EmailConfig{Provider: "smtp"}
	h.emailSender = &fakeEmailSender{}
	return h, repo, user, secret
}

func apiChallenge(t *testing.T, h *Handler) string {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"email":"mfa@example.com","password":"a sufficiently long password"}`))
	w := httptest.NewRecorder()
	h.APILogin(w, request)
	var body struct {
		Token  string `json:"challenge_token"`
		Access string `json:"access_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != http.StatusAccepted || body.Token == "" || body.Access != "" {
		t.Fatalf("challenge: %d %s", w.Code, w.Body.String())
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("API challenge set cookies")
	}
	return body.Token
}

func verifyAPI(h *Handler, token, code string) *httptest.ResponseRecorder {
	value, _ := json.Marshal(map[string]string{"challenge_token": token, "code": code})
	w := httptest.NewRecorder()
	h.APIVerifyMFA(w, httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa", strings.NewReader(string(value))))
	return w
}

func TestMFAPasswordAPILoginRecoveryAndReplay(t *testing.T) {
	h, _, user, secret := mfaFixture(t, "totp")
	challenge := apiChallenge(t, h)
	if user.LastLoginAt != nil {
		t.Fatal("recorded login before MFA")
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/private", nil)
	r.Header.Set("Authorization", "Bearer "+challenge)
	h.Authenticate(h.RequireUser(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("challenge gained account access") }))).ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("challenge auth status %d", w.Code)
	}
	code, _ := appauth.TOTPCode(secret, time.Now().Unix()/30)
	w = verifyAPI(h, challenge, code)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "access_token") || user.LastLoginAt == nil {
		t.Fatalf("verification failed: %d %s", w.Code, w.Body.String())
	}
	if verifyAPI(h, challenge, code).Code != http.StatusUnauthorized {
		t.Fatal("challenge replay accepted")
	}
	user.MFA.SentAt = time.Time{}
	second := apiChallenge(t, h)
	if verifyAPI(h, second, code).Code != http.StatusUnauthorized {
		t.Fatal("TOTP replay accepted on another challenge")
	}
	if verifyAPI(h, second, strings.Repeat("a", 32)).Code != http.StatusOK || len(user.MFA.Recovery) != 0 {
		t.Fatal("recovery code not consumed")
	}
	user.MFA.SentAt = time.Time{}
	third := apiChallenge(t, h)
	if verifyAPI(h, third, strings.Repeat("a", 32)).Code != http.StatusUnauthorized {
		t.Fatal("recovery replay accepted")
	}
}

func TestMFAEmailDeliveryResendAndFailureBudget(t *testing.T) {
	h, _, user, _ := mfaFixture(t, "email")
	challenge := apiChallenge(t, h)
	sender := h.emailSender.(*fakeEmailSender)
	if len(sender.messages) != 1 || sender.messages[0].To != user.Email {
		t.Fatal("email not addressed to account")
	}
	code := strings.Split(sender.messages[0].Text, ": ")[1][:6]
	if strings.Contains(user.MFA.EmailHash, code) {
		t.Fatal("plaintext email code stored")
	}
	resend := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		data, _ := json.Marshal(map[string]string{"challenge_token": challenge})
		h.APIResendMFA(w, httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/resend", strings.NewReader(string(data))))
		return w
	}
	if resend().Code != http.StatusTooManyRequests || len(sender.messages) != 1 {
		t.Fatal("resend cooldown bypass")
	}
	if verifyAPI(h, challenge, "wrong").Code != http.StatusUnauthorized {
		t.Fatal("wrong code accepted")
	}
	user.MFA.SentAt = time.Now().Add(-time.Minute)
	expires := user.MFA.Expires
	if resend().Code != http.StatusOK || len(sender.messages) != 2 || user.MFA.Failures != 1 || !user.MFA.Expires.Equal(expires) {
		t.Fatal("resend reset budget or expiry")
	}
	for range 4 {
		verifyAPI(h, challenge, "wrong")
	}
	newCode := strings.Split(sender.messages[1].Text, ": ")[1][:6]
	if verifyAPI(h, challenge, newCode).Code != http.StatusUnauthorized || user.MFA.LockedUntil.IsZero() {
		t.Fatal("lockout bypass")
	}
	user.MFA.SentAt = time.Time{}
	w := httptest.NewRecorder()
	h.beginMFA(w, httptest.NewRequest("POST", "/login", nil), user, "login", "", transportBearer)
	if w.Code != http.StatusTooManyRequests {
		t.Fatal("new challenge bypassed lockout")
	}
	user.MFA.LockedUntil = time.Now().Add(-time.Second)
	challenge = apiChallenge(t, h)
	newCode = strings.Split(sender.messages[len(sender.messages)-1].Text, ": ")[1][:6]
	if verifyAPI(h, challenge, newCode).Code != http.StatusOK {
		t.Fatal("correct email code rejected after lockout")
	}
}

func TestMFAChallengeRechecksAccountAndExpiry(t *testing.T) {
	for _, change := range []string{"disabled", "banned", "version", "email", "expired", "superseded"} {
		t.Run(change, func(t *testing.T) {
			h, _, user, _ := mfaFixture(t, "totp")
			token := apiChallenge(t, h)
			switch change {
			case "disabled":
				user.Active = false
			case "banned":
				user.ModerationStatus = db.ModerationBanned
			case "version":
				user.TokenVersion++
			case "email":
				user.Email = "changed@example.com"
			case "expired":
				user.MFA.Expires = time.Now().Add(-time.Second)
			case "superseded":
				user.MFA.Challenge = "another"
			}
			if verifyAPI(h, token, strings.Repeat("a", 32)).Code != http.StatusUnauthorized {
				t.Fatal("stale challenge accepted")
			}
		})
	}
}

func TestMFAEnrollmentCSRFProofAndSessionInvalidation(t *testing.T) {
	h, repo, user, _ := mfaFixture(t, "")
	access, claims := issueTestJWT(t, h, user)
	start := func(csrf, password string) *httptest.ResponseRecorder {
		r := formRequest("/account/mfa", url.Values{"action": {"setup-totp"}, "csrf_token": {csrf}, "current_password": {password}})
		r.AddCookie(&http.Cookie{Name: h.jwtCookieName(), Value: access})
		w := httptest.NewRecorder()
		h.Authenticate(h.RequireUser(http.HandlerFunc(h.BeginMFAChange))).ServeHTTP(w, r)
		return w
	}
	if start("bad", "a sufficiently long password").Code != http.StatusForbidden {
		t.Fatal("CSRF bypass")
	}
	if w := start(claims.CSRF, "wrong"); !strings.Contains(w.Body.String(), "Confirm your current password") || user.MFA.Challenge != "" {
		t.Fatal("password reauthentication bypass")
	}
	w := start(claims.CSRF, "a sufficiently long password")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Enter a setup key") || user.MFA.Method != "" {
		t.Fatalf("setup %d %s", w.Code, w.Body.String())
	}
	secret, err := appauth.OpenMFASecret(h.settingsKey, user.ID, user.MFA.PendingSecret)
	if err != nil {
		t.Fatal(err)
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == h.mfaCookieName() {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("missing hardened challenge cookie")
	}
	challenge, err := h.jwt.ParseMFA(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := appauth.TOTPCode(secret, time.Now().Unix()/30)
	verify := func(code, csrf string, authenticated bool) *httptest.ResponseRecorder {
		r := formRequest("/login/mfa", url.Values{"code": {code}, "csrf_token": {csrf}})
		r.AddCookie(cookie)
		if authenticated {
			r.AddCookie(&http.Cookie{Name: h.jwtCookieName(), Value: access})
		}
		w := httptest.NewRecorder()
		h.Authenticate(http.HandlerFunc(h.VerifyMFA)).ServeHTTP(w, r)
		return w
	}
	if verify(code, "bad", true).Code != http.StatusForbidden {
		t.Fatal("challenge CSRF bypass")
	}
	verify(code, challenge.CSRF, false)
	if user.MFA.Method != "" {
		t.Fatal("enrolled without original authenticated session")
	}
	w = verify(code, challenge.CSRF, true)
	if !strings.Contains(w.Body.String(), "Save your recovery codes") || user.MFA.Method != "totp" || len(user.MFA.Recovery) != 10 || user.TokenVersion != 2 || user.MFA.PendingSecret != "" {
		t.Fatalf("enrollment failed: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), secret) {
		t.Fatal("enrolled secret exposed")
	}
	r := httptest.NewRequest("GET", "/account", nil)
	r.AddCookie(&http.Cookie{Name: h.jwtCookieName(), Value: access})
	w = httptest.NewRecorder()
	h.Authenticate(h.RequireUser(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("old JWT retained access") }))).ServeHTTP(w, r)
	if repo.users[user.ID].TokenVersion != 2 {
		t.Fatal("token version lost")
	}
}

func TestMFAOAuthAndEmailOutageRecovery(t *testing.T) {
	h, repo, user, _ := mfaFixture(t, "email")
	user.PasswordHash = ""
	identity := &db.OAuthIdentity{Provider: "google", Subject: "external-user", UserID: user.ID, Email: user.Email}
	if err := repo.LinkOAuthIdentity(t.Context(), identity); err != nil {
		t.Fatal(err)
	}
	h.emailSender.(*fakeEmailSender).err = errors.New("delivery unavailable")
	w := httptest.NewRecorder()
	h.finishOAuthLogin(w, httptest.NewRequest("GET", "/oauth/google/callback", nil), oauthFlow{Next: loginDestinationAdminUsers}, identity, user.Email, user.DisplayName)
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == h.jwtCookieName() && c.Value != "" {
			t.Fatal("OAuth bypassed MFA")
		}
		if c.Name == h.mfaCookieName() {
			cookie = c
		}
	}
	if cookie == nil || !strings.Contains(w.Body.String(), "could not confirm delivery") {
		t.Fatalf("OAuth challenge missing: %s", w.Body.String())
	}
	claims, _ := h.jwt.ParseMFA(cookie.Value)
	r := formRequest("/login/mfa", url.Values{"csrf_token": {claims.CSRF}, "code": {strings.Repeat("a", 32)}})
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.VerifyMFA(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/admin/users" {
		t.Fatalf("recovery or redirect failed: %d %s", w.Code, w.Header().Get("Location"))
	}
}

func TestMFADisableAndRecoveryReplacementRequireProof(t *testing.T) {
	for _, action := range []string{"disable", "recovery"} {
		t.Run(action, func(t *testing.T) {
			h, _, user, _ := mfaFixture(t, "totp")
			access, claims := issueTestJWT(t, h, user)
			r := formRequest("/account/mfa", url.Values{"csrf_token": {claims.CSRF}, "action": {action}})
			r.AddCookie(&http.Cookie{Name: h.jwtCookieName(), Value: access})
			w := httptest.NewRecorder()
			h.Authenticate(h.RequireUser(http.HandlerFunc(h.BeginMFAChange))).ServeHTTP(w, r)
			if user.MFA.Method != "totp" || user.TokenVersion != 1 {
				t.Fatal("settings changed before proof")
			}
			var cookie *http.Cookie
			for _, c := range w.Result().Cookies() {
				if c.Name == h.mfaCookieName() {
					cookie = c
				}
			}
			if cookie == nil {
				t.Fatalf("missing challenge %d %s", w.Code, w.Body.String())
			}
			challenge, _ := h.jwt.ParseMFA(cookie.Value)
			verify := func(code string) *httptest.ResponseRecorder {
				r := formRequest("/login/mfa", url.Values{"csrf_token": {challenge.CSRF}, "code": {code}})
				r.AddCookie(cookie)
				r.AddCookie(&http.Cookie{Name: h.jwtCookieName(), Value: access})
				w := httptest.NewRecorder()
				h.Authenticate(http.HandlerFunc(h.VerifyMFA)).ServeHTTP(w, r)
				return w
			}
			verify("wrong")
			if user.MFA.Method != "totp" || user.TokenVersion != 1 {
				t.Fatal("settings changed without factor")
			}
			w = verify(strings.Repeat("a", 32))
			if user.TokenVersion != 2 {
				t.Fatal("settings did not invalidate sessions")
			}
			if action == "disable" {
				if user.MFA.Method != "" || len(user.MFA.Recovery) != 0 || user.MFA.Secret != "" || w.Code != http.StatusSeeOther {
					t.Fatal("MFA not cleared")
				}
			} else {
				if user.MFA.Method != "totp" || len(user.MFA.Recovery) != 10 || !strings.Contains(w.Body.String(), "Save your recovery codes") {
					t.Fatal("codes not regenerated")
				}
				oldHash := appauth.MFAHash(h.settingsKey, user.ID+":recovery", strings.Repeat("a", 32))
				for _, hash := range user.MFA.Recovery {
					if hash == oldHash {
						t.Fatal("old recovery code retained")
					}
				}
			}
		})
	}
}

func TestMFAEmailEnrollmentPrerequisitesAndConfirmation(t *testing.T) {
	h, _, user, _ := mfaFixture(t, "")
	access, claims := issueTestJWT(t, h, user)
	start := func() *httptest.ResponseRecorder {
		r := formRequest("/account/mfa", url.Values{"csrf_token": {claims.CSRF}, "action": {"setup-email"}, "current_password": {"a sufficiently long password"}})
		r.AddCookie(&http.Cookie{Name: h.jwtCookieName(), Value: access})
		w := httptest.NewRecorder()
		h.Authenticate(h.RequireUser(http.HandlerFunc(h.BeginMFAChange))).ServeHTTP(w, r)
		return w
	}
	verified := user.EmailVerifiedAt
	user.EmailVerifiedAt = nil
	start()
	if user.MFA.Challenge != "" {
		t.Fatal("unverified email enrolled")
	}
	user.EmailVerifiedAt = verified
	h.config.Email.Provider = "none"
	start()
	if user.MFA.Challenge != "" {
		t.Fatal("disabled email provider enrolled")
	}
	h.config.Email.Provider = "smtp"
	w := start()
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == h.mfaCookieName() {
			cookie = c
		}
	}
	if cookie == nil || user.MFA.Method != "" {
		t.Fatal("invalid pending email enrollment")
	}
	challenge, _ := h.jwt.ParseMFA(cookie.Value)
	message := h.emailSender.(*fakeEmailSender).messages[0]
	code := strings.Split(message.Text, ": ")[1][:6]
	r := formRequest("/login/mfa", url.Values{"csrf_token": {challenge.CSRF}, "code": {code}})
	r.AddCookie(cookie)
	r.AddCookie(&http.Cookie{Name: h.jwtCookieName(), Value: access})
	w = httptest.NewRecorder()
	h.Authenticate(http.HandlerFunc(h.VerifyMFA)).ServeHTTP(w, r)
	if user.MFA.Method != "email" || user.TokenVersion != 2 || len(user.MFA.Recovery) != 10 {
		t.Fatalf("email enrollment failed %s", w.Body.String())
	}
}

func TestMFABrowserPasswordLoginAndTransportIsolation(t *testing.T) {
	h, _, user, _ := mfaFixture(t, "totp")
	h.config.SecureCookies = true
	page := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/login", nil)
	csrf := h.preAuthCSRF(page, r)
	r = formRequest("/login", url.Values{"csrf_token": {csrf}, "email": {user.Email}, "password": {"a sufficiently long password"}, "next": {loginDestinationAdminUsers}})
	r.AddCookie(page.Result().Cookies()[0])
	r.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	h.Login(w, r)
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == h.jwtCookieName() && c.Value != "" {
			t.Fatal("password login bypassed MFA")
		}
		if c.Name == h.mfaCookieName() {
			cookie = c
		}
	}
	if cookie == nil || !cookie.Secure || !cookie.HttpOnly || !strings.HasPrefix(cookie.Name, "__Host-") {
		t.Fatal("missing secure MFA cookie")
	}
	if !strings.Contains(w.Body.String(), "Complete verification") || w.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatal("challenge render failed")
	}
	if verifyAPI(h, cookie.Value, strings.Repeat("a", 32)).Code != http.StatusUnauthorized {
		t.Fatal("browser challenge usable through bearer API")
	}
	claims, _ := h.jwt.ParseMFA(cookie.Value)
	r = formRequest("/login/mfa", url.Values{"csrf_token": {claims.CSRF}, "code": {strings.Repeat("a", 32)}})
	r.AddCookie(cookie)
	r.Header.Set("HX-Request", "true")
	w = httptest.NewRecorder()
	h.VerifyMFA(w, r)
	if w.Header().Get("HX-Redirect") != "/admin/users" {
		t.Fatal("HTMX destination was not preserved")
	}
}

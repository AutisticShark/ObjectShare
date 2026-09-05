package htmx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/AutisticShark/ObjectShare/email"
)

type fakeEmailSender struct {
	messages []email.Message
	err      error
}

func (s *fakeEmailSender) Send(_ context.Context, m email.Message) error {
	s.messages = append(s.messages, m)
	return s.err
}

func TestEmailSettingsSecretLifecycle(t *testing.T) {
	c := config.EmailConfig{Provider: "ses", FromAddress: "sender@example.com", SMTP: config.SMTPConfig{Password: "old-smtp"}, Alibaba: config.AlibabaMailConfig{AccessKeyID: "old-alibaba-id", AccessKeySecret: "old-alibaba-secret"}, SES: config.SESConfig{AccessKeyID: "old-ses-id", SecretAccessKey: "old-ses-secret", SessionToken: "old-ses-token"}}
	fields := map[string]*string{"smtp_password": &c.SMTP.Password, "alibaba_access_key_id": &c.Alibaba.AccessKeyID, "alibaba_access_key_secret": &c.Alibaba.AccessKeySecret, "ses_access_key_id": &c.SES.AccessKeyID, "ses_secret_access_key": &c.SES.SecretAccessKey, "ses_session_token": &c.SES.SessionToken}
	for _, mode := range []string{"preserve", "replace", "clear"} {
		values := url.Values{"email_provider": {"ses"}, "email_from_address": {"sender@example.com"}, "email_timeout": {"20s"}, "email_smtp_port": {"587"}, "email_ses_region": {"us-east-1"}}
		old := c
		for field := range fields {
			values.Set("email_"+field, "")
			if mode != "preserve" {
				values.Set("email_"+field, "replacement-"+field)
			}
			if mode == "clear" {
				values.Set("clear_email_"+field, "on")
			}
		}
		request := httptest.NewRequest("POST", "/admin/settings", strings.NewReader(values.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := request.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if err := updateEmailFromForm(&c, request); err != nil {
			t.Fatal(err)
		}
		if mode == "preserve" && (c.SMTP.Password != old.SMTP.Password || c.Alibaba != old.Alibaba || c.SES.AccessKeyID != old.SES.AccessKeyID || c.SES.SecretAccessKey != old.SES.SecretAccessKey || c.SES.SessionToken != old.SES.SessionToken) {
			t.Fatal("blank fields lost credentials")
		}
		for field, target := range fields {
			if mode == "replace" && *target != "replacement-"+field {
				t.Fatal("secret replacement failed")
			}
			if mode == "clear" && *target != "" {
				t.Fatal("clear must override replacement")
			}
		}
	}
	before := c
	request := httptest.NewRequest("POST", "/admin/settings", nil)
	_ = request.ParseForm()
	if err := updateEmailFromForm(&c, request); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c, before) {
		t.Fatal("older form cleared email settings")
	}
}

func TestEmailTestActionAuthorizationCSRFAndRecipient(t *testing.T) {
	repository := newAuthMemoryRepository()
	admin := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "admin@example.com", Role: db.RoleAdmin, Active: true, TokenVersion: 1}
	user := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa56", Email: "user@example.com", Role: db.RoleUser, Active: true, TokenVersion: 1}
	repository.users[admin.ID] = admin
	repository.users[user.ID] = user
	handler := newAuthTestHandler(t, repository, false)
	sender := &fakeEmailSender{}
	handler.emailSender = sender
	adminToken, adminClaims := issueTestJWT(t, handler, admin)
	userToken, _ := issueTestJWT(t, handler, user)
	protected := handler.Authenticate(handler.RequireAdmin(http.HandlerFunc(handler.AdminTestEmail)))
	for _, tc := range []struct {
		name, token, csrf string
		want              int
	}{{"anonymous", "", "", http.StatusUnauthorized}, {"normal user", userToken, "", http.StatusForbidden}, {"missing CSRF", adminToken, "", http.StatusForbidden}, {"bad CSRF", adminToken, "wrong", http.StatusForbidden}, {"valid administrator", adminToken, adminClaims.CSRF, http.StatusSeeOther}} {
		t.Run(tc.name, func(t *testing.T) {
			values := url.Values{"csrf_token": {tc.csrf}, "to": {"attacker@example.com"}, "subject": {"attacker subject"}, "email_provider": {"smtp"}, "email_smtp_host": {"attacker.example.com"}}
			request := httptest.NewRequest("POST", "/admin/settings/email/test", strings.NewReader(values.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.token != "" {
				request.AddCookie(&http.Cookie{Name: "objectshare_jwt", Value: tc.token})
			}
			response := httptest.NewRecorder()
			protected.ServeHTTP(response, request)
			if response.Code != tc.want {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if tc.name == "valid administrator" {
				if response.Header().Get("Location") != "/admin/settings?message=email-sent" {
					t.Fatal("wrong success redirect")
				}
			} else if len(sender.messages) != 0 {
				t.Fatal("unauthorized email sent")
			}
		})
	}
	if len(sender.messages) != 1 || sender.messages[0].To != admin.Email || sender.messages[0].Subject != "ObjectShare test email" {
		t.Fatal("test action accepted user-controlled message or recipient")
	}
}

func TestEmailTestActionDisabledFailureAndFormBounds(t *testing.T) {
	repository := newAuthMemoryRepository()
	handler := newAuthTestHandler(t, repository, false)
	admin := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "admin@example.com", Role: db.RoleAdmin, Active: true, TokenVersion: 1}
	repository.users[admin.ID] = admin
	token, claims := issueTestJWT(t, handler, admin)
	protected := handler.Authenticate(handler.RequireAdmin(http.HandlerFunc(handler.AdminTestEmail)))
	for _, tc := range []struct {
		name   string
		sender *fakeEmailSender
		body   string
		want   int
	}{{"disabled", &fakeEmailSender{err: email.ErrDisabled}, "", 503}, {"failure", &fakeEmailSender{err: errors.New("provider-secret-echo")}, "", 502}, {"oversized", &fakeEmailSender{}, strings.Repeat("x", 129*1024), 400}} {
		t.Run(tc.name, func(t *testing.T) {
			handler.emailSender = tc.sender
			values := url.Values{"csrf_token": {claims.CSRF}, "data": {tc.body}}
			request := httptest.NewRequest("POST", "/admin/settings/email/test", strings.NewReader(values.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.AddCookie(&http.Cookie{Name: "objectshare_jwt", Value: token})
			response := httptest.NewRecorder()
			protected.ServeHTTP(response, request)
			if response.Code != tc.want || strings.Contains(response.Body.String(), "provider-secret-echo") {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if tc.name == "oversized" && len(tc.sender.messages) != 0 {
				t.Fatal("oversized form sent email")
			}
		})
	}
}

func TestEmailTestActionUsesSharedRateLimit(t *testing.T) {
	repository := newAuthMemoryRepository()
	handler := newAuthTestHandler(t, repository, false)
	admin := &db.User{ID: "60c628c1-85cb-4463-b895-a629c31bfa55", Email: "admin@example.com", Role: db.RoleAdmin, Active: true, TokenVersion: 1}
	repository.users[admin.ID] = admin
	token, claims := issueTestJWT(t, handler, admin)
	limits := &recordingRateLimitRepository{allowed: false}
	handler.config.RateLimit = &config.RateLimitConfig{Enabled: true, Window: config.Duration(time.Minute)}
	handler.rateLimits = limits
	sender := &fakeEmailSender{}
	handler.emailSender = sender
	request := httptest.NewRequest("POST", "/admin/settings/email/test", strings.NewReader(url.Values{"csrf_token": {claims.CSRF}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: "objectshare_jwt", Value: token})
	response := httptest.NewRecorder()
	handler.Authenticate(handler.RequireAdmin(http.HandlerFunc(handler.AdminTestEmail))).ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" || response.Header().Get("X-RateLimit-Limit") != "3" || limits.scope != "email-test" || len(sender.messages) != 0 {
		t.Fatal("shared email rate limit did not prevent delivery")
	}
}

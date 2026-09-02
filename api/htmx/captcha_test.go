package htmx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
	"github.com/google/uuid"
)

func TestTurnstileVerifierBindsActionHostnameAndClientIP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if err := request.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if request.FormValue("secret") != "server-secret" || request.FormValue("response") != "browser-token" ||
			request.FormValue("remoteip") != "203.0.113.8" || request.FormValue("idempotency_key") == "" {
			t.Fatalf("unexpected Siteverify form: %#v", request.Form)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(writer, `{"success":true,"hostname":"share.example.com","action":"upload"}`)
	}))
	defer server.Close()

	verifier := &turnstileVerifier{secretKey: "server-secret", expectedHostname: "share.example.com", verifyURL: server.URL, client: &http.Client{Timeout: time.Second}}
	if err := verifier.Verify(context.Background(), "browser-token", "203.0.113.8", "upload"); err != nil {
		t.Fatal(err)
	}
}

func TestTurnstileVerifierRejectsMissingTokenActionAndHostname(t *testing.T) {
	if err := (&turnstileVerifier{}).Verify(context.Background(), "", "", "login"); !errors.Is(err, errCaptchaInvalid) {
		t.Fatalf("missing token error = %v", err)
	}
	for _, test := range []struct {
		name, response, hostname, action string
	}{
		{"wrong action", `{"success":true,"hostname":"share.example.com","action":"signup"}`, "share.example.com", "login"},
		{"wrong hostname", `{"success":true,"hostname":"attacker.example","action":"login"}`, "share.example.com", "login"},
		{"provider rejection", `{"success":false,"error-codes":["timeout-or-duplicate"]}`, "", "login"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprint(writer, test.response)
			}))
			defer server.Close()
			verifier := &turnstileVerifier{secretKey: "secret", expectedHostname: test.hostname, verifyURL: server.URL, client: server.Client()}
			if err := verifier.Verify(context.Background(), "token", "", test.action); !errors.Is(err, errCaptchaInvalid) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestTurnstileVerifierFailsClosedWhenProviderIsUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "upstream error", http.StatusBadGateway)
	}))
	defer server.Close()
	verifier := &turnstileVerifier{secretKey: "secret", verifyURL: server.URL, client: server.Client()}
	if err := verifier.Verify(context.Background(), "token", "", "download"); !errors.Is(err, errCaptchaUnavailable) {
		t.Fatalf("error = %v", err)
	}
}

type captchaVerifierFunc func(context.Context, string, string, string) error

func (verify captchaVerifierFunc) Verify(ctx context.Context, token, remoteIP, action string) error {
	return verify(ctx, token, remoteIP, action)
}

func TestCaptchaProtectedDownloadRejectsGETAndValidatesPOSTBeforeLookup(t *testing.T) {
	repository := &memoryRepository{files: make(map[string]*db.FileList)}
	handler := newTestHandler(t, repository, &memoryStorage{objects: make(map[string][]byte)})
	handler.config.Captcha = &config.CaptchaConfig{Provider: "turnstile", SiteKey: "site", SecretKey: "secret", ProtectDownload: true}
	verified := false
	handler.captcha = captchaVerifierFunc(func(_ context.Context, token, remoteIP, action string) error {
		verified = true
		if token != "valid-token" || action != "download" {
			return errCaptchaInvalid
		}
		return nil
	})

	router := chi.NewRouter()
	router.Get("/api/v1/download/{id}", handler.Download)
	router.Post("/api/v1/download/{id}", handler.Download)
	getResponse := httptest.NewRecorder()
	router.ServeHTTP(getResponse, httptest.NewRequest(http.MethodGet, "/api/v1/download/"+uuid.NewString(), nil))
	if getResponse.Code != http.StatusMethodNotAllowed || verified {
		t.Fatalf("GET status=%d verified=%v", getResponse.Code, verified)
	}

	postResponse := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/download/"+uuid.NewString(), strings.NewReader("cf-turnstile-response=valid-token"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(postResponse, request)
	if postResponse.Code != http.StatusNotFound || !verified {
		t.Fatalf("POST status=%d verified=%v body=%q", postResponse.Code, verified, postResponse.Body.String())
	}
}

func TestCaptchaRejectsLoginAndSignupBeforeAccountWork(t *testing.T) {
	repository := newAuthMemoryRepository()
	adminID := uuid.NewString()
	repository.users[adminID] = &db.User{ID: adminID, Email: "admin@example.com", DisplayName: "Admin", Role: db.RoleAdmin, Active: true, TokenVersion: 1}
	handler := newAuthTestHandler(t, repository, false)
	handler.config.Captcha = &config.CaptchaConfig{Provider: "turnstile", SiteKey: "site", SecretKey: "secret", ProtectLogin: true, ProtectSignup: true}
	var actions []string
	handler.captcha = captchaVerifierFunc(func(_ context.Context, _, _, action string) error {
		actions = append(actions, action)
		return errCaptchaInvalid
	})

	for _, test := range []struct {
		path   string
		page   func(http.ResponseWriter, *http.Request)
		submit func(http.ResponseWriter, *http.Request)
		values url.Values
	}{
		{"/login", handler.LoginPage, handler.Login, url.Values{"email": {"admin@example.com"}, "password": {"password"}, "cf-turnstile-response": {"rejected-token"}}},
		{"/signup", handler.SignupPage, handler.Signup, url.Values{"display_name": {"New User"}, "email": {"new@example.com"}, "password": {"a sufficiently long password"}, "password_confirm": {"a sufficiently long password"}, "cf-turnstile-response": {"rejected-token"}}},
	} {
		pageResponse := httptest.NewRecorder()
		test.page(pageResponse, httptest.NewRequest(http.MethodGet, test.path, nil))
		test.values.Set("csrf_token", strings.TrimSpace(pageResponse.Body.String()))
		request := formRequest(test.path, test.values)
		request.AddCookie(pageResponse.Result().Cookies()[0])
		response := httptest.NewRecorder()
		test.submit(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s status=%d body=%q", test.path, response.Code, response.Body.String())
		}
	}
	if len(actions) != 2 || actions[0] != "login" || actions[1] != "signup" {
		t.Fatalf("verified actions = %#v", actions)
	}
	if _, err := repository.UserByEmail(context.Background(), "new@example.com"); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("CAPTCHA-rejected signup created a user: %v", err)
	}
}

func TestCaptchaRejectsUploadBeforeReservationOrStorage(t *testing.T) {
	repository := &memoryRepository{files: make(map[string]*db.FileList)}
	storage := &memoryStorage{objects: make(map[string][]byte)}
	handler := newTestHandler(t, repository, storage)
	handler.config.Captcha = &config.CaptchaConfig{Provider: "turnstile", SiteKey: "site", SecretKey: "secret", ProtectUpload: true}
	handler.captcha = captchaVerifierFunc(func(_ context.Context, _, _, action string) error {
		if action != "upload" {
			t.Fatalf("action = %q", action)
		}
		return errCaptchaInvalid
	})

	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	file, err := form.CreateFormFile("file", "payload.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.Write([]byte("payload"))
	_ = form.WriteField("cf-turnstile-response", "rejected-token")
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/upload", &body)
	request.Header.Set("Content-Type", form.FormDataContentType())
	response := httptest.NewRecorder()
	handler.Upload(response, request)
	if response.Code != http.StatusForbidden || len(repository.files) != 0 || len(storage.objects) != 0 {
		t.Fatalf("status=%d files=%d objects=%d", response.Code, len(repository.files), len(storage.objects))
	}
}

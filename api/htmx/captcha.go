package htmx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/google/uuid"
)

const turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

var (
	errCaptchaInvalid     = errors.New("captcha validation failed")
	errCaptchaUnavailable = errors.New("captcha validation service unavailable")
)

type captchaWidget struct {
	SiteKey string
	Action  string
}

type captchaVerifier interface {
	Verify(context.Context, string, string, string) error
}

type turnstileVerifier struct {
	secretKey        string
	expectedHostname string
	verifyURL        string
	client           *http.Client
}

type turnstileResponse struct {
	Success    bool     `json:"success"`
	Hostname   string   `json:"hostname"`
	Action     string   `json:"action"`
	ErrorCodes []string `json:"error-codes"`
}

func newCaptchaVerifier(settings *config.CaptchaConfig) captchaVerifier {
	if settings == nil || settings.Provider != "turnstile" {
		return nil
	}
	return &turnstileVerifier{
		secretKey: settings.SecretKey, expectedHostname: settings.ExpectedHostname,
		verifyURL: turnstileVerifyURL,
		client:    &http.Client{Timeout: 8 * time.Second},
	}
}

func (verifier *turnstileVerifier) Verify(ctx context.Context, token, remoteIP, expectedAction string) error {
	token = strings.TrimSpace(token)
	if token == "" || len(token) > 2048 {
		return errCaptchaInvalid
	}
	values := url.Values{
		"secret":          {verifier.secretKey},
		"response":        {token},
		"idempotency_key": {uuid.NewString()},
	}
	if remoteIP != "" {
		values.Set("remoteip", remoteIP)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, verifier.verifyURL, strings.NewReader(values.Encode()))
	if err != nil {
		return fmt.Errorf("%w: create request: %v", errCaptchaUnavailable, err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := verifier.client.Do(request)
	if err != nil {
		return fmt.Errorf("%w: request: %v", errCaptchaUnavailable, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("%w: HTTP %d", errCaptchaUnavailable, response.StatusCode)
	}
	var result turnstileResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64*1024))
	if err := decoder.Decode(&result); err != nil {
		return fmt.Errorf("%w: decode response: %v", errCaptchaUnavailable, err)
	}
	if !result.Success || result.Action != expectedAction {
		return fmt.Errorf("%w: action=%q codes=%s", errCaptchaInvalid, result.Action, strings.Join(result.ErrorCodes, ","))
	}
	if verifier.expectedHostname != "" && !strings.EqualFold(result.Hostname, verifier.expectedHostname) {
		return fmt.Errorf("%w: hostname mismatch", errCaptchaInvalid)
	}
	return nil
}

func (handler *Handler) captchaEnabled(action string) bool {
	settings := handler.config.Captcha
	if settings == nil || settings.Provider == "none" || handler.captcha == nil {
		return false
	}
	switch action {
	case "login":
		return settings.ProtectLogin
	case "signup":
		return settings.ProtectSignup
	case "upload":
		return settings.ProtectUpload
	case "download":
		return settings.ProtectDownload
	default:
		return false
	}
}

func (handler *Handler) captchaWidget(action string) *captchaWidget {
	if !handler.captchaEnabled(action) {
		return nil
	}
	return &captchaWidget{SiteKey: handler.config.Captcha.SiteKey, Action: action}
}

func (handler *Handler) verifyCaptcha(writer http.ResponseWriter, request *http.Request, action, suppliedToken string) bool {
	if !handler.captchaEnabled(action) {
		return true
	}
	token := strings.TrimSpace(suppliedToken)
	if token == "" {
		token = strings.TrimSpace(request.Header.Get("X-Captcha-Token"))
	}
	if token == "" {
		token = request.FormValue("cf-turnstile-response")
	}
	err := handler.captcha.Verify(request.Context(), token, handler.clientIP(request), action)
	if err == nil {
		return true
	}
	if errors.Is(err, errCaptchaUnavailable) {
		handler.logger.Error("captcha verification unavailable", "action", action, "error", err)
		http.Error(writer, "CAPTCHA verification is temporarily unavailable. Try again shortly.", http.StatusServiceUnavailable)
		return false
	}
	handler.logger.Warn("captcha verification rejected", "action", action, "error", err)
	http.Error(writer, "Complete the CAPTCHA challenge and try again.", http.StatusForbidden)
	return false
}

func (handler *Handler) CaptchaCSPEnabled() bool {
	return handler.config.Captcha != nil && handler.config.Captcha.Provider == "turnstile"
}

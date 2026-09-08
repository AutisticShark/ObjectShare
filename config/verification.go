package config

import (
	"errors"
	"net/url"
	"strings"
)

func (cfg *ServiceConfig) validateEmailVerification() error {
	c := &cfg.Auth.EmailVerification
	c.PublicURL = strings.TrimRight(strings.TrimSpace(c.PublicURL), "/")
	if c.PublicURL != "" {
		u, err := url.Parse(c.PublicURL)
		if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "" || (u.Scheme != "https" && u.Scheme != "http") || (cfg.SecureCookies && u.Scheme != "https") {
			return errors.New("auth.email_verification.public_url must be an HTTP(S) origin without credentials, path, query, or fragment; HTTPS is required with secure cookies")
		}
	}
	if c.RequireForPurchases || c.RequireForUploads {
		if c.PublicURL == "" || cfg.Email == nil || strings.TrimSpace(cfg.Email.Provider) == "" || strings.EqualFold(strings.TrimSpace(cfg.Email.Provider), "none") {
			return errors.New("email verification restrictions require auth.email_verification.public_url and an enabled email provider")
		}
	}
	return nil
}

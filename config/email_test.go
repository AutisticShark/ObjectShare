package config

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func validEmailConfig(provider string) EmailConfig {
	return EmailConfig{Provider: provider, FromAddress: "sender@example.com", FromName: "ObjectShare",
		SMTP:    SMTPConfig{Host: "smtp.example.com", Username: "user", Password: "smtp-secret"},
		Alibaba: AlibabaMailConfig{AccessKeyID: "alibaba-id", AccessKeySecret: "alibaba-secret"},
		SES:     SESConfig{AccessKeyID: "ses-id", SecretAccessKey: "ses-secret", SessionToken: "ses-token"}}
}

func TestEmailProviderValidationMatrix(t *testing.T) {
	for _, provider := range []string{"none", "smtp", "alibaba", "ses"} {
		t.Run(provider, func(t *testing.T) {
			c := validEmailConfig(provider)
			if err := c.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, tc := range []struct {
		name, provider string
		change         func(*EmailConfig)
	}{
		{"unknown", "bad", func(*EmailConfig) {}},
		{"sender injection", "smtp", func(c *EmailConfig) { c.FromAddress = "sender@example.com\r\nBcc: other@example.com" }},
		{"sender list", "smtp", func(c *EmailConfig) { c.FromAddress = "a@example.com,b@example.com" }},
		{"quoted comma", "alibaba", func(c *EmailConfig) { c.FromAddress = `"a,b"@example.com` }},
		{"display name", "ses", func(c *EmailConfig) { c.FromAddress = "Name <sender@example.com>" }},
		{"reply injection", "ses", func(c *EmailConfig) { c.ReplyTo = "reply@example.com\r\nX: y" }},
		{"name injection", "smtp", func(c *EmailConfig) { c.FromName = "Name\nBcc: evil" }},
		{"unicode mailbox", "ses", func(c *EmailConfig) { c.FromAddress = "名字@example.com" }},
		{"timeout negative", "none", func(c *EmailConfig) { c.Timeout = -1 }},
		{"timeout excessive", "smtp", func(c *EmailConfig) { c.Timeout = Duration(2 * time.Minute) }},
		{"host URL", "smtp", func(c *EmailConfig) { c.SMTP.Host = "https://smtp.example.com" }},
		{"host with port", "smtp", func(c *EmailConfig) { c.SMTP.Host = "smtp.example.com:587" }},
		{"plaintext", "smtp", func(c *EmailConfig) { c.SMTP.TLSMode = "none" }},
		{"port", "smtp", func(c *EmailConfig) { c.SMTP.Port = 65536 }},
		{"missing password", "smtp", func(c *EmailConfig) { c.SMTP.Password = "" }},
		{"missing username", "smtp", func(c *EmailConfig) { c.SMTP.Username = "" }},
		{"Alibaba key missing", "alibaba", func(c *EmailConfig) { c.Alibaba.AccessKeySecret = "" }},
		{"Alibaba region", "alibaba", func(c *EmailConfig) { c.Alibaba.Region = "evil.example.com" }},
		{"Alibaba name", "alibaba", func(c *EmailConfig) { c.FromName = strings.Repeat("字", 16) }},
		{"SES partial keys", "ses", func(c *EmailConfig) { c.SES.SecretAccessKey = "" }},
		{"SES token only", "ses", func(c *EmailConfig) { c.SES.AccessKeyID = ""; c.SES.SecretAccessKey = "" }},
		{"SES region URL", "ses", func(c *EmailConfig) { c.SES.Region = "us-east-1/evil" }},
		{"SES configuration set", "ses", func(c *EmailConfig) { c.SES.ConfigurationSet = "set\r\nevil" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validEmailConfig(tc.provider)
			tc.change(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("invalid settings accepted")
			}
		})
	}
	for _, region := range []string{"cn-hangzhou", "ap-southeast-1", "ap-southeast-2", "us-east-1", "eu-central-1"} {
		c := validEmailConfig("alibaba")
		c.Alibaba.Region = region
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	c := validEmailConfig("ses")
	c.SES = SESConfig{Region: "us-gov-west-1"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c = validEmailConfig("smtp")
	c.SMTP = SMTPConfig{Host: "::1", TLSMode: "tls"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.SMTP.Port != 465 {
		t.Fatal("implicit TLS port default")
	}
}

func TestEmailEnvironmentAndEncryptedRuntime(t *testing.T) {
	for key, value := range map[string]string{
		"PROVIDER": "ses", "FROM_ADDRESS": "sender@example.com", "FROM_NAME": "Example", "REPLY_TO": "reply@example.com", "TIMEOUT": "22s",
		"SMTP_HOST": "smtp.example.com", "SMTP_PORT": "2465", "SMTP_TLS_MODE": "tls", "SMTP_USERNAME": "user", "SMTP_PASSWORD": "smtp-secret",
		"ALIBABA_REGION": "ap-southeast-1", "ALIBABA_ACCESS_KEY_ID": "alibaba-id", "ALIBABA_ACCESS_KEY_SECRET": "alibaba-secret",
		"SES_REGION": "eu-west-1", "SES_ACCESS_KEY_ID": "ses-id", "SES_SECRET_ACCESS_KEY": "ses-secret", "SES_SESSION_TOKEN": "ses-token", "SES_CONFIGURATION_SET": "events",
	} {
		t.Setenv("OBJECTSHARE_EMAIL_"+key, value)
	}
	cfg := testDefaults()
	if err := applyEnvironment(cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	c := cfg.Email
	if c.Provider != "ses" || c.FromAddress != "sender@example.com" || c.FromName != "Example" || c.ReplyTo != "reply@example.com" || c.Timeout.Duration() != 22*time.Second || c.SMTP != (SMTPConfig{Host: "smtp.example.com", Port: 2465, TLSMode: "tls", Username: "user", Password: "smtp-secret"}) || c.Alibaba != (AlibabaMailConfig{Region: "ap-southeast-1", AccessKeyID: "alibaba-id", AccessKeySecret: "alibaba-secret"}) || c.SES != (SESConfig{Region: "eu-west-1", AccessKeyID: "ses-id", SecretAccessKey: "ses-secret", SessionToken: "ses-token", ConfigurationSet: "events"}) {
		t.Fatal("environment fields did not map to expected email config")
	}
	runtime := RuntimeFromService(cfg)
	sealed, err := SealRuntime(runtime, testJWTSecret)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"smtp-secret", "alibaba-id", "alibaba-secret", "ses-id", "ses-secret", "ses-token"} {
		if strings.Contains(sealed, secret) {
			t.Fatal("plaintext email credential in sealed document")
		}
	}
	opened, err := OpenRuntime(sealed, testJWTSecret)
	if err != nil {
		t.Fatal(err)
	}
	fresh := testDefaults()
	if err := ApplyRuntime(fresh, opened); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fresh.Email, c) {
		t.Fatal("email config did not survive encrypted runtime round trip")
	}
	// Older database documents omit email entirely and must still load disabled.
	var legacy RuntimeConfig
	data, err := json.Marshal(RuntimeFromService(testDefaults()))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		t.Fatal(err)
	}
	legacy.Email = EmailConfig{}
	if err := ApplyRuntime(fresh, legacy); err != nil {
		t.Fatal(err)
	}
	if fresh.Email.Provider != "none" || fresh.Email.Timeout.Duration() != 15*time.Second {
		t.Fatal("legacy email defaults")
	}
}

func TestEmailBootstrapDefersStaleSeedValidation(t *testing.T) {
	t.Setenv("OBJECTSHARE_JWT_SECRET", testJWTSecret)
	t.Setenv("OBJECTSHARE_EMAIL_SMTP_PORT", "invalid")
	cfg, err := LoadBootstrap("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ValidateSeed() == nil {
		t.Fatal("invalid initial seed accepted")
	}
	if err := ApplyRuntime(cfg, RuntimeFromService(testDefaults())); err != nil {
		t.Fatal("stale seed blocked authoritative runtime:", err)
	}
}

func TestEmailExampleConfiguration(t *testing.T) {
	data, err := os.ReadFile("../config.json.example")
	if err != nil {
		t.Fatal(err)
	}
	var cfg ServiceConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Email == nil || cfg.Email.Provider != "none" {
		t.Fatal("example must explicitly disable email")
	}
	if err := cfg.Email.Validate(); err != nil {
		t.Fatal(err)
	}
}

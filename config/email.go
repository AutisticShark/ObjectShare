package config

import (
	"errors"
	"net"
	"net/mail"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// EmailConfig is database-owned. Only the selected provider must be configured.
type EmailConfig struct {
	Provider    string            `json:"provider"`
	FromAddress string            `json:"from_address"`
	FromName    string            `json:"from_name"`
	ReplyTo     string            `json:"reply_to"`
	Timeout     Duration          `json:"timeout"`
	SMTP        SMTPConfig        `json:"smtp"`
	Alibaba     AlibabaMailConfig `json:"alibaba"`
	SES         SESConfig         `json:"ses"`
}

type SMTPConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	TLSMode  string `json:"tls_mode"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type AlibabaMailConfig struct {
	Region          string `json:"region"`
	AccessKeyID     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
}

type SESConfig struct {
	Region           string `json:"region"`
	AccessKeyID      string `json:"access_key_id"`
	SecretAccessKey  string `json:"secret_access_key"`
	SessionToken     string `json:"session_token"`
	ConfigurationSet string `json:"configuration_set"`
}

// ValidEmailAddress accepts one ASCII mailbox, without display names, lists,
// control characters, or SMTPUTF8 requirements. Display names are separate.
func ValidEmailAddress(value string) bool {
	if len(value) > 254 || strings.ContainsAny(value, "\r\n\x00,;<>\"()[]\\") {
		return false
	}
	for _, r := range value {
		if r < 33 || r > 126 {
			return false
		}
	}
	parsed, err := mail.ParseAddress(value)
	return err == nil && parsed.Name == "" && parsed.Address == value && strings.Contains(value, "@")
}

var emailRegionPattern = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)
var emailConfigSetPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func (c *EmailConfig) Validate() error {
	c.Provider = strings.ToLower(strings.TrimSpace(c.Provider))
	if c.Provider == "" {
		c.Provider = "none"
	}
	if c.Timeout == 0 {
		c.Timeout = Duration(15 * time.Second)
	}
	if c.SMTP.TLSMode == "" {
		c.SMTP.TLSMode = "starttls"
	}
	if c.SMTP.Port == 0 {
		c.SMTP.Port = 587
		if c.SMTP.TLSMode == "tls" {
			c.SMTP.Port = 465
		}
	}
	if c.Alibaba.Region == "" {
		c.Alibaba.Region = "cn-hangzhou"
	}
	if c.SES.Region == "" {
		c.SES.Region = "us-east-1"
	}
	if c.Timeout.Duration() < time.Second || c.Timeout.Duration() > time.Minute {
		return errors.New("email timeout must be between 1s and 1m")
	}
	switch c.Provider {
	case "none":
		return nil
	case "smtp", "alibaba", "ses":
	default:
		return errors.New("email provider must be none, smtp, alibaba, or ses")
	}
	if !ValidEmailAddress(c.FromAddress) {
		return errors.New("email from_address must be a single ASCII email address")
	}
	if c.ReplyTo != "" && !ValidEmailAddress(c.ReplyTo) {
		return errors.New("email reply_to must be a single ASCII email address")
	}
	if !utf8.ValidString(c.FromName) || strings.ContainsAny(c.FromName, "\r\n\x00") || utf8.RuneCountInString(c.FromName) > 100 {
		return errors.New("email from_name must contain at most 100 characters and no line breaks")
	}
	switch c.Provider {
	case "smtp":
		if c.SMTP.Host == "" || strings.ContainsAny(c.SMTP.Host, " /\\\r\n\t\x00") || (strings.Contains(c.SMTP.Host, ":") && net.ParseIP(c.SMTP.Host) == nil) {
			return errors.New("email SMTP host must be a hostname or IP without a port")
		}
		if c.SMTP.Port < 1 || c.SMTP.Port > 65535 {
			return errors.New("email SMTP port must be between 1 and 65535")
		}
		if c.SMTP.TLSMode != "starttls" && c.SMTP.TLSMode != "tls" {
			return errors.New("email SMTP tls_mode must be starttls or tls")
		}
		if (c.SMTP.Username == "") != (c.SMTP.Password == "") {
			return errors.New("email SMTP username and password must both be set or both be empty")
		}
	case "alibaba":
		switch c.Alibaba.Region {
		case "cn-hangzhou", "ap-southeast-1", "ap-southeast-2", "us-east-1", "eu-central-1":
		default:
			return errors.New("email Alibaba region is not supported")
		}
		if c.Alibaba.AccessKeyID == "" || c.Alibaba.AccessKeySecret == "" {
			return errors.New("email Alibaba access_key_id and access_key_secret are required")
		}
		if utf8.RuneCountInString(c.FromName) > 15 {
			return errors.New("email Alibaba from_name must contain at most 15 characters")
		}
	case "ses":
		if !emailRegionPattern.MatchString(c.SES.Region) {
			return errors.New("email SES region is invalid")
		}
		if (c.SES.AccessKeyID == "") != (c.SES.SecretAccessKey == "") || (c.SES.SessionToken != "" && c.SES.AccessKeyID == "") {
			return errors.New("email SES credentials require an access key pair, or leave all fields empty for the AWS credential chain")
		}
		if c.SES.ConfigurationSet != "" && !emailConfigSetPattern.MatchString(c.SES.ConfigurationSet) {
			return errors.New("email SES configuration_set must contain 1 to 64 letters, numbers, underscores, or hyphens")
		}
	}
	return nil
}

func applyEmailEnvironment(c *EmailConfig) error {
	for name, target := range map[string]*string{
		"PROVIDER": &c.Provider, "FROM_ADDRESS": &c.FromAddress, "FROM_NAME": &c.FromName, "REPLY_TO": &c.ReplyTo,
		"SMTP_HOST": &c.SMTP.Host, "SMTP_TLS_MODE": &c.SMTP.TLSMode, "SMTP_USERNAME": &c.SMTP.Username, "SMTP_PASSWORD": &c.SMTP.Password,
		"ALIBABA_REGION": &c.Alibaba.Region, "ALIBABA_ACCESS_KEY_ID": &c.Alibaba.AccessKeyID, "ALIBABA_ACCESS_KEY_SECRET": &c.Alibaba.AccessKeySecret,
		"SES_REGION": &c.SES.Region, "SES_ACCESS_KEY_ID": &c.SES.AccessKeyID, "SES_SECRET_ACCESS_KEY": &c.SES.SecretAccessKey, "SES_SESSION_TOKEN": &c.SES.SessionToken, "SES_CONFIGURATION_SET": &c.SES.ConfigurationSet,
	} {
		setString("OBJECTSHARE_EMAIL_"+name, target)
	}
	return errors.Join(setInt("OBJECTSHARE_EMAIL_SMTP_PORT", &c.SMTP.Port), setDuration("OBJECTSHARE_EMAIL_TIMEOUT", &c.Timeout))
}

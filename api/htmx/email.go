package htmx

import (
	"errors"
	"net/http"
	"strings"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/AutisticShark/ObjectShare/email"
)

// AdminTestEmail uses the active provider and a server-owned message addressed
// only to the authenticated administrator. Pending/posted settings never send.
func (handler *Handler) AdminTestEmail(writer http.ResponseWriter, request *http.Request) {
	identity := currentIdentity(request)
	if identity == nil || identity.User == nil || identity.User.Role != db.RoleAdmin {
		http.Error(writer, "Administrator access required.", http.StatusForbidden)
		return
	}
	if !handler.parseSettingsForm(writer, request) || !handler.verifyJWTCSRF(writer, request, identity) {
		return
	}
	if !handler.allowRequest(writer, request, "email-test", 3) {
		return
	}
	if handler.emailSender == nil {
		http.Error(writer, "Email delivery is disabled. Configure a provider, save, and restart every replica.", http.StatusServiceUnavailable)
		return
	}
	err := handler.emailSender.Send(request.Context(), email.Message{
		To: identity.User.Email, Subject: "ObjectShare test email",
		Text: "This is a test email from ObjectShare. Your active email provider accepted this message for delivery.",
	})
	if errors.Is(err, email.ErrDisabled) {
		http.Error(writer, "Email delivery is disabled. Configure a provider, save, and restart every replica.", http.StatusServiceUnavailable)
		return
	}
	if err != nil {
		// The delivery layer returns only local diagnostics, but keep this route
		// independent of provider error formats and injected Sender implementations.
		http.Error(writer, "Test email failed. Check the active provider credentials, sender verification, region, and network access. Restart after saving configuration changes.", http.StatusBadGateway)
		return
	}
	handler.redirect(writer, request, "/admin/settings?message=email-sent")
}

func updateEmailFromForm(c *config.EmailConfig, request *http.Request) error {
	// Preserve email configuration for older clients that omit the new section.
	if _, present := request.Form["email_provider"]; !present {
		return nil
	}
	for field, target := range map[string]*string{
		"provider": &c.Provider, "from_address": &c.FromAddress, "from_name": &c.FromName, "reply_to": &c.ReplyTo,
		"smtp_host": &c.SMTP.Host, "smtp_tls_mode": &c.SMTP.TLSMode, "smtp_username": &c.SMTP.Username,
		"alibaba_region": &c.Alibaba.Region, "ses_region": &c.SES.Region, "ses_configuration_set": &c.SES.ConfigurationSet,
	} {
		*target = strings.TrimSpace(request.FormValue("email_" + field))
	}
	for field, target := range map[string]*string{
		"smtp_password": &c.SMTP.Password, "alibaba_access_key_id": &c.Alibaba.AccessKeyID, "alibaba_access_key_secret": &c.Alibaba.AccessKeySecret,
		"ses_access_key_id": &c.SES.AccessKeyID, "ses_secret_access_key": &c.SES.SecretAccessKey, "ses_session_token": &c.SES.SessionToken,
	} {
		*target = updatedSecret(request, "email_"+field, "clear_email_"+field, *target)
	}
	return errors.Join(formInt(request, "email_smtp_port", &c.SMTP.Port), formDuration(request, "email_timeout", &c.Timeout))
}

package config

import "testing"

func TestEmailVerificationConfigurationMatrix(t *testing.T) {
	for _, purchases := range []bool{false, true} {
		for _, uploads := range []bool{false, true} {
			for _, provider := range []string{"none", "smtp"} {
				for _, origin := range []string{"", "https://files.example.com"} {
					cfg := testDefaults()
					cfg.Email = &EmailConfig{Provider: provider}
					cfg.Auth.EmailVerification = EmailVerificationConfig{PublicURL: origin, RequireForPurchases: purchases, RequireForUploads: uploads}
					wantError := (purchases || uploads) && (provider == "none" || origin == "")
					if err := cfg.validateEmailVerification(); (err != nil) != wantError {
						t.Fatalf("purchases=%v uploads=%v provider=%s origin=%q: %v", purchases, uploads, provider, origin, err)
					}
				}
			}
		}
	}
	for _, origin := range []string{"javascript:alert(1)", "https://user:pass@example.com", "https://example.com/path", "https://example.com?x=y", "https://example.com?", "https://example.com/#token", "//example.com", "http://example.com"} {
		cfg := testDefaults()
		cfg.SecureCookies = true
		cfg.Auth.EmailVerification.PublicURL = origin
		if cfg.validateEmailVerification() == nil {
			t.Errorf("accepted invalid verification origin %q", origin)
		}
	}
}

func TestEmailVerificationEnvironmentAndEncryptedRuntime(t *testing.T) {
	t.Setenv("OBJECTSHARE_EMAIL_VERIFICATION_PUBLIC_URL", "https://files.example.com/")
	t.Setenv("OBJECTSHARE_EMAIL_VERIFICATION_REQUIRE_FOR_PURCHASES", "true")
	t.Setenv("OBJECTSHARE_EMAIL_VERIFICATION_REQUIRE_FOR_UPLOADS", "true")
	cfg := testDefaults()
	if err := applyEnvironment(cfg); err != nil {
		t.Fatal(err)
	}
	// Supply an enabled provider for the normal runtime validation path.
	cfg.Email = &EmailConfig{Provider: "smtp", FromAddress: "sender@example.com", SMTP: SMTPConfig{Host: "smtp.example.com", Port: 587, TLSMode: "starttls"}}
	runtime, err := NormalizeRuntime(cfg, RuntimeFromService(cfg))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := SealRuntime(runtime, testJWTSecret)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenRuntime(sealed, testJWTSecret)
	if err != nil {
		t.Fatal(err)
	}
	other := testDefaults()
	if err := ApplyRuntime(other, opened); err != nil {
		t.Fatal(err)
	}
	want := EmailVerificationConfig{PublicURL: "https://files.example.com", RequireForPurchases: true, RequireForUploads: true}
	if other.Auth.EmailVerification != want {
		t.Fatalf("lost verification policy: %#v", other.Auth.EmailVerification)
	}
}

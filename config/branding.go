package config

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// BrandingConfig is part of the encrypted, database-owned runtime document.
// Text is plain text; assets are loaded by the browser, never fetched by the server.
type BrandingConfig struct {
	SiteName       string `json:"site_name"`
	Tagline        string `json:"tagline"`
	LogoURL        string `json:"logo_url"`
	HeaderImageURL string `json:"header_image_url"`
	FaviconURL     string `json:"favicon_url"`
	FooterMessage  string `json:"footer_message"`
	FooterLinkText string `json:"footer_link_text"`
	FooterLinkURL  string `json:"footer_link_url"`
}

func (c BrandingConfig) Display() BrandingConfig {
	if strings.TrimSpace(c.SiteName) == "" {
		c.SiteName = "ObjectShare"
	}
	return c
}

func (c *BrandingConfig) Validate() error {
	for _, field := range []struct {
		name      string
		value     *string
		limit     int
		multiline bool
	}{
		{"site_name", &c.SiteName, 80, false},
		{"tagline", &c.Tagline, 240, false},
		{"footer_message", &c.FooterMessage, 2000, true},
		{"footer_link_text", &c.FooterLinkText, 80, false},
	} {
		*field.value = strings.TrimSpace(*field.value)
		if !utf8.ValidString(*field.value) || utf8.RuneCountInString(*field.value) > field.limit {
			return fmt.Errorf("branding.%s must contain at most %d valid Unicode characters", field.name, field.limit)
		}
		for _, r := range *field.value {
			if unicode.IsControl(r) && !(field.multiline && (r == '\n' || r == '\r' || r == '\t')) {
				return fmt.Errorf("branding.%s contains unsupported control characters", field.name)
			}
		}
	}
	c.SiteName = c.Display().SiteName
	for _, field := range []struct {
		name  string
		value *string
	}{
		{"logo_url", &c.LogoURL}, {"header_image_url", &c.HeaderImageURL},
		{"favicon_url", &c.FaviconURL}, {"footer_link_url", &c.FooterLinkURL},
	} {
		*field.value = strings.TrimSpace(*field.value)
		if *field.value != "" && !validBrandingURL(*field.value) {
			return fmt.Errorf("branding.%s must be an HTTPS URL without credentials or fragment, or a root-relative path (maximum 2048 bytes)", field.name)
		}
	}
	if (c.FooterLinkText == "") != (c.FooterLinkURL == "") {
		return fmt.Errorf("branding footer link requires both text and URL")
	}
	return nil
}

func validBrandingURL(value string) bool {
	if len(value) > 2048 || !utf8.ValidString(value) || strings.ContainsAny(value, "\\\"'<>;") || strings.ContainsFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return false
	}
	u, err := url.Parse(value)
	if err != nil || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	if strings.ContainsAny(u.Path, "\\\r\n\x00") {
		return false
	}
	if strings.HasPrefix(value, "/") {
		return !strings.HasPrefix(value, "//") && !strings.HasPrefix(u.Path, "//") && u.Host == "" && u.Scheme == ""
	}
	if u.Scheme != "https" || u.Hostname() == "" {
		return false
	}
	// Restrict origins to literal hosts, so they can also be used as CSP sources.
	if net.ParseIP(u.Hostname()) == nil {
		for _, r := range u.Hostname() {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
				return false
			}
		}
	}
	if strings.HasSuffix(u.Host, ":") {
		return false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	return true
}

// ImageSources returns only the configured HTTPS image origins for CSP.
func (c BrandingConfig) ImageSources() []string {
	var sources []string
	seen := map[string]bool{}
	for _, value := range []string{c.LogoURL, c.HeaderImageURL, c.FaviconURL} {
		if !validBrandingURL(value) {
			continue
		}
		u, _ := url.Parse(value)
		if u.Scheme != "https" {
			continue
		}
		origin := "https://" + u.Host
		if !seen[origin] {
			sources = append(sources, origin)
			seen[origin] = true
		}
	}
	return sources
}

func applyBrandingEnvironment(c *BrandingConfig) {
	for name, target := range map[string]*string{
		"SITE_NAME": &c.SiteName, "TAGLINE": &c.Tagline, "LOGO_URL": &c.LogoURL,
		"HEADER_IMAGE_URL": &c.HeaderImageURL, "FAVICON_URL": &c.FaviconURL,
		"FOOTER_MESSAGE": &c.FooterMessage, "FOOTER_LINK_TEXT": &c.FooterLinkText, "FOOTER_LINK_URL": &c.FooterLinkURL,
	} {
		setString("OBJECTSHARE_BRANDING_"+name, target)
	}
}

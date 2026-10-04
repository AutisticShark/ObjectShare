package htmx

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
)

func TestTemplatesReferenceAssetsByContentHash(t *testing.T) {
	// Every /assets/ reference must go through the asset function, otherwise
	// browsers and CDNs keep a stale copy for the day-long cache lifetime.
	pages, err := os.ReadFile("../../template/partials.html")
	if err != nil {
		t.Fatal(err)
	}
	templates, _ := os.ReadDir("../../template")
	unversioned := regexp.MustCompile(`(?:src|href)="/assets/`)
	for _, entry := range templates {
		if !strings.HasSuffix(entry.Name(), ".html") {
			continue
		}
		contents, err := os.ReadFile("../../template/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		if match := unversioned.Find(contents); match != nil {
			t.Errorf("%s references an asset without {{asset}}: %s", entry.Name(), match)
		}
	}
	if !bytes.Contains(pages, []byte(`{{asset "/assets/branding.css"}}`)) {
		t.Fatal("the shared head does not version branding.css")
	}

	parsed, err := parseTemplates(os.DirFS("../.."), config.BrandingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	user := &db.User{ID: "user", Role: db.RoleAdmin}
	var output bytes.Buffer
	if err := parsed.ExecuteTemplate(&output, "admin_users.html", adminPageData{User: user}); err != nil {
		t.Fatal(err)
	}
	theme, _ := os.ReadFile("../../template/theme.js")
	themeURL, _ := assetURLFunc(fstest.MapFS{"template/theme.js": {Data: theme}})("/assets/theme.js")
	for _, want := range []string{themeURL, `href="/assets/branding.css?v=`, `src="/assets/admin-users.js?v=`, `href="/assets/admin-users.css?v=`} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("rendered page is missing %q", want)
		}
	}
}

func TestAssetVersionFollowsContent(t *testing.T) {
	first := assetURLFunc(fstest.MapFS{"template/branding.css": {Data: []byte(".a{}")}})
	second := assetURLFunc(fstest.MapFS{"template/branding.css": {Data: []byte(".b{}")}})
	again := assetURLFunc(fstest.MapFS{"template/branding.css": {Data: []byte(".a{}")}})
	a, err := first("/assets/branding.css")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := second("/assets/branding.css")
	c, _ := again("/assets/branding.css")
	if !strings.HasPrefix(a, "/assets/branding.css?v=") || a == b || a != c {
		t.Fatalf("asset versions do not follow content: %q %q %q", a, b, c)
	}
	if _, err := first("/assets/missing.js"); err == nil {
		t.Fatal("an unknown asset was accepted")
	}
}

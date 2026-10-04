package htmx

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
)

// assetFiles maps each public asset URL to the embedded file that serves it.
var assetFiles = map[string]string{
	"/assets/admin-users.css":      "template/admin_users.css",
	"/assets/admin-users.js":       "template/admin_users.js",
	"/assets/branding.css":         "template/branding.css",
	"/assets/captcha.js":           "template/captcha.js",
	"/assets/client-encryption.js": "template/client-encryption.js",
	"/assets/sharing.js":           "template/sharing.js",
	"/assets/theme.js":             "template/theme.js",
	"/assets/upload.js":            "template/upload.js",
}

// assetURLFunc returns the "asset" template function, which adds a content
// hash to an asset URL. Assets are cached for a day, so the URL must change
// whenever an upgrade or a configuration reload changes their content. The
// hashes are computed once, from the same files the handler serves.
func assetURLFunc(files fs.FS) func(string) (string, error) {
	urls := make(map[string]string, len(assetFiles))
	for path, name := range assetFiles {
		// New reports a missing asset; a test template set may omit some.
		if data, err := fs.ReadFile(files, name); err == nil {
			sum := sha256.Sum256(data)
			urls[path] = path + "?v=" + hex.EncodeToString(sum[:8])
		}
	}
	return func(path string) (string, error) {
		if url, ok := urls[path]; ok {
			return url, nil
		}
		if _, known := assetFiles[path]; known {
			return path, nil
		}
		return "", fmt.Errorf("unknown asset %q", path)
	}
}

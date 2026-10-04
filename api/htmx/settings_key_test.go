package htmx

import (
	"strings"
	"testing"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/db"
)

// After a settings-key rotation, recovery codes made with the previous key are
// marked and keep working only while that key is configured; TOTP secrets a
// stale replica sealed with the previous key still open.
func TestPreviousSettingsKeyKeepsRecoveryCodesAndSecretsUsable(t *testing.T) {
	current, previous := "current-settings-key-with-at-least-32-bytes", "previous-settings-key-with-at-least-32-bytes"
	userID, code := "11111111-1111-4111-8111-111111111111", strings.Repeat("a", 32)
	marked := db.PreviousKeyRecoveryPrefix + appauth.MFAHash(previous, userID+":recovery", code)
	fresh := appauth.MFAHash(current, userID+":recovery", code)

	rotating := &Handler{settingsKey: current, priorSettingsKey: previous}
	if !rotating.recoveryCodeMatches(userID, code, marked) || !rotating.recoveryCodeMatches(userID, code, fresh) {
		t.Fatal("previous-key and current-key recovery codes must both match during a rotation")
	}
	if rotating.recoveryCodeMatches(userID, code, appauth.MFAHash(previous, userID+":recovery", code)) {
		t.Fatal("an unmarked hash must be checked with the current key only")
	}
	if rotating.recoveryCodeMatches(userID, strings.Repeat("b", 32), marked) {
		t.Fatal("a wrong recovery code matched")
	}
	rotated := &Handler{settingsKey: current}
	if rotated.recoveryCodeMatches(userID, code, marked) || !rotated.recoveryCodeMatches(userID, code, fresh) {
		t.Fatal("without the previous key only current-key codes may match")
	}

	sealed, err := appauth.SealMFASecret(previous, userID, "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	if secret, err := rotating.openMFASecret(userID, sealed); err != nil || secret != "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" {
		t.Fatalf("previous-key secret did not open during a rotation: %v", err)
	}
	if _, err := rotated.openMFASecret(userID, sealed); err == nil {
		t.Fatal("a previous-key secret opened without the previous key")
	}
}

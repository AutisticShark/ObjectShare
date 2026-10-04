package htmx

import (
	"crypto/subtle"
	"strings"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/db"
)

// recoveryCodeMatches checks a recovery code against one stored hash. Hashes
// marked during a settings-key rotation were made with the previous key and
// match only while that key is still configured.
func (handler *Handler) recoveryCodeMatches(userID, code, saved string) bool {
	key := handler.settingsKey
	if hash, previous := strings.CutPrefix(saved, db.PreviousKeyRecoveryPrefix); previous {
		if handler.priorSettingsKey == "" {
			return false
		}
		key, saved = handler.priorSettingsKey, hash
	}
	hash := appauth.MFAHash(key, userID+":recovery", code)
	return subtle.ConstantTimeCompare([]byte(hash), []byte(saved)) == 1
}

// openMFASecret opens a TOTP secret with the settings key and, during a
// rotation, with the previous key. Start-up re-seals every stored secret, but
// a replica still running the old key may enrol one before it restarts.
func (handler *Handler) openMFASecret(userID, sealed string) (string, error) {
	secret, err := appauth.OpenMFASecret(handler.settingsKey, userID, sealed)
	if err != nil && handler.priorSettingsKey != "" {
		if previous, previousErr := appauth.OpenMFASecret(handler.priorSettingsKey, userID, sealed); previousErr == nil {
			return previous, nil
		}
	}
	return secret, err
}

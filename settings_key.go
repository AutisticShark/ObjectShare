package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
)

type settingsKeyRotator interface {
	RotateSettingsKey(context.Context, func(string) (string, bool, error), func(*db.User) (bool, bool, error)) (db.SettingsKeyRotation, error)
}

// rotateSettingsKey moves everything still protected by settings_key_previous
// to settings_key before the configuration document is opened: the document
// itself and every account's TOTP secrets. Recovery codes are stored only as
// keyed hashes, so they are marked as previous-key codes instead.
func rotateSettingsKey(ctx context.Context, repository settingsKeyRotator, cfg *config.ServiceConfig, logger *slog.Logger) error {
	if cfg.SettingsKeyPrevious == "" {
		return nil
	}
	result, err := repository.RotateSettingsKey(ctx,
		func(value string) (string, bool, error) {
			return config.ResealRuntime(value, cfg.SettingsKey, cfg.SettingsKeyPrevious)
		},
		func(user *db.User) (bool, bool, error) {
			return resealMFA(user, cfg.SettingsKey, cfg.SettingsKeyPrevious)
		})
	if err != nil {
		return fmt.Errorf("rotate settings key: %w", err)
	}
	if result.Rotated {
		logger.Info("settings key rotated: the configuration and MFA secrets now use settings_key", "accounts_updated", result.Accounts)
	}
	if result.Unreadable > 0 {
		logger.Warn("some accounts have an MFA secret that neither settings key opens; those users must set up MFA again", "accounts", result.Unreadable)
	}
	if result.PreviousKeyRecoveryAccounts > 0 {
		logger.Warn("accounts still hold MFA recovery codes made with the previous settings key; they work only while settings_key_previous is set, so ask those users to generate new recovery codes before removing it", "accounts", result.PreviousKeyRecoveryAccounts)
	} else {
		logger.Info("no data depends on the previous settings key any more; remove settings_key_previous (OBJECTSHARE_SETTINGS_KEY_PREVIOUS)")
	}
	return nil
}

// resealMFA re-encrypts an account's TOTP secrets with currentKey and marks
// its recovery-code hashes as previous-key hashes. Hashes already marked were
// made with an even older key that is no longer available and are dropped.
// A pending email code is not converted; it expires and can be resent.
func resealMFA(user *db.User, currentKey, previousKey string) (changed, unreadable bool, err error) {
	for _, sealed := range []*string{&user.MFA.Secret, &user.MFA.PendingSecret, &user.MFA.Manage.PendingSecret} {
		if *sealed == "" {
			continue
		}
		if _, openErr := appauth.OpenMFASecret(currentKey, user.ID, *sealed); openErr == nil {
			continue
		}
		secret, openErr := appauth.OpenMFASecret(previousKey, user.ID, *sealed)
		if openErr != nil {
			unreadable = true
			continue
		}
		if *sealed, err = appauth.SealMFASecret(currentKey, user.ID, secret); err != nil {
			return false, false, fmt.Errorf("re-seal MFA secret: %w", err)
		}
		changed = true
	}
	var recovery []string
	for _, hash := range user.MFA.Recovery {
		changed = true
		if !strings.HasPrefix(hash, db.PreviousKeyRecoveryPrefix) {
			recovery = append(recovery, db.PreviousKeyRecoveryPrefix+hash)
		}
	}
	user.MFA.Recovery = recovery
	return changed, unreadable, nil
}

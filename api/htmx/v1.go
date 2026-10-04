package htmx

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/AutisticShark/ObjectShare/email"
	appcrypto "github.com/AutisticShark/ObjectShare/encryption"
	"github.com/AutisticShark/ObjectShare/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

const mebibyte = int64(1024 * 1024)

type Handler struct {
	clientEncryptionJS []byte
	emailSender        email.Sender
	config             *config.ServiceConfig
	repository         db.Repository
	storage            service.ObjectStore
	direct             service.DirectUploader
	directPolicy       service.DirectUploadPolicy
	templates          *template.Template
	brandingCSS        []byte
	themeJS            []byte
	sharingJS          []byte
	uploadJS           []byte
	captchaJS          []byte
	adminUsersJS       []byte
	adminUsersCSS      []byte
	htmxErrorsJS       []byte
	cipher             *appcrypto.Cipher // encrypts new uploads; nil while encryption is off
	readCipher         *appcrypto.Cipher // decrypts stored objects whenever a key is configured
	cipherSlot         chan struct{}
	logger             *slog.Logger
	users              db.AuthRepository
	jwt                *appauth.JWTManager
	csrfSecret         []byte
	oauthSecret        []byte
	downloadSecret     []byte
	oauthProviders     map[string]appauth.OAuthProvider
	captcha            captchaVerifier
	rateLimits         db.RateLimitRepository
	settings           db.SettingsRepository
	billing            db.BillingRepository
	billingGateways    map[string]billingGateway
	settingsKey        string
	localRateLimits    *localRateLimiter
	trustedProxies     []*net.IPNet
	reloadConfig       func(context.Context) error
	// adminsExistUntil is the Unix-nanosecond deadline until which SetupComplete
	// may skip its AdminCount query after seeing an administrator.
	adminsExistUntil atomic.Int64
	// cleanupMu guards the background pass over expired upload reservations.
	cleanupMu      sync.Mutex
	cleanupRunning bool
	// inlineCleanup makes cleanupExpiredUploads finish before it returns. It is
	// off in production (cleanup runs in the background) and on in tests that
	// inspect repository and storage state right after a request.
	inlineCleanup bool
	lastCleanup   time.Time
}

// InheritProcessState carries state that belongs to the process rather than to
// a configuration revision across a hot reload, so activating a saved revision
// neither invalidates pre-authentication CSRF tokens nor resets the local
// rate-limit windows that protect a replica without a shared repository.
func (handler *Handler) InheritProcessState(previous *Handler) {
	if previous == nil {
		return
	}
	handler.csrfSecret = previous.csrfSecret
	handler.localRateLimits = previous.localRateLimits
}

// SetConfigReloader registers the callback that activates a saved
// configuration revision in this replica without a restart. Handlers built
// without one keep the previous restart-to-activate behaviour.
func (handler *Handler) SetConfigReloader(reload func(context.Context) error) {
	handler.reloadConfig = reload
}

// preAuthCSRFSecret keys the pre-authentication (login, signup, setup) CSRF
// tokens. It is derived from the JWT secret, like the OAuth and download-form
// secrets, so every replica and every restart accepts the same tokens. Only a
// configuration without authentication falls back to a per-process random key.
func preAuthCSRFSecret(cfg *config.ServiceConfig) ([]byte, error) {
	if cfg.Auth != nil && cfg.Auth.JWTSecret != "" {
		derived := sha256.Sum256([]byte("objectshare-preauth-csrf-v1\x00" + cfg.Auth.JWTSecret))
		return derived[:], nil
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate CSRF secret: %w", err)
	}
	return secret, nil
}

func New(cfg *config.ServiceConfig, repository db.Repository, storage service.ObjectStore, templates fs.FS, logger *slog.Logger) (*Handler, error) {
	parsed, err := parseTemplates(templates, cfg.Branding)
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	brandingCSS, err := fs.ReadFile(templates, "template/branding.css")
	if err != nil {
		return nil, fmt.Errorf("read branding stylesheet: %w", err)
	}
	themeJS, err := fs.ReadFile(templates, "template/theme.js")
	if err != nil {
		return nil, fmt.Errorf("read theme script: %w", err)
	}
	sharingJS, err := fs.ReadFile(templates, "template/sharing.js")
	if err != nil {
		return nil, fmt.Errorf("read sharing script: %w", err)
	}
	uploadJS, err := fs.ReadFile(templates, "template/upload.js")
	if err != nil {
		return nil, fmt.Errorf("read upload script: %w", err)
	}
	clientEncryptionJS, err := fs.ReadFile(templates, "template/client-encryption.js")
	if err != nil {
		return nil, fmt.Errorf("read client encryption script: %w", err)
	}
	captchaJS, err := fs.ReadFile(templates, "template/captcha.js")
	if err != nil {
		return nil, fmt.Errorf("read CAPTCHA script: %w", err)
	}
	adminUsersJS, err := fs.ReadFile(templates, "template/admin_users.js")
	if err != nil {
		return nil, fmt.Errorf("read administrator user script: %w", err)
	}
	adminUsersCSS, err := fs.ReadFile(templates, "template/admin_users.css")
	if err != nil {
		return nil, fmt.Errorf("read administrator user stylesheet: %w", err)
	}
	htmxErrorsJS, err := fs.ReadFile(templates, "template/htmx-errors.js")
	if err != nil {
		return nil, fmt.Errorf("read HTMX error script: %w", err)
	}
	csrfSecret, err := preAuthCSRFSecret(cfg)
	if err != nil {
		return nil, err
	}
	userRepository, _ := repository.(db.AuthRepository)
	var trustedProxyCIDRs []string
	if cfg.RateLimit != nil {
		trustedProxyCIDRs = cfg.RateLimit.TrustedProxyCIDRs
	}
	trustedProxies, err := parseTrustedProxies(trustedProxyCIDRs)
	if err != nil {
		return nil, fmt.Errorf("configure trusted proxies: %w", err)
	}
	rateLimits, _ := repository.(db.RateLimitRepository)
	settings, _ := repository.(db.SettingsRepository)
	billing, _ := repository.(db.BillingRepository)
	billingGateways := configuredBillingGateways(cfg.Billing)
	if cfg.RateLimit != nil && cfg.RateLimit.Enabled && rateLimits == nil {
		return nil, errors.New("enabled rate limiting requires a shared rate-limit repository")
	}
	handler := &Handler{
		config: cfg, repository: repository, users: userRepository, storage: storage,
		clientEncryptionJS: clientEncryptionJS, templates: parsed, sharingJS: sharingJS, brandingCSS: brandingCSS, themeJS: themeJS, uploadJS: uploadJS, captchaJS: captchaJS,
		adminUsersJS: adminUsersJS, adminUsersCSS: adminUsersCSS, logger: logger, csrfSecret: csrfSecret,
		captcha: newCaptchaVerifier(cfg.Captcha), rateLimits: rateLimits,
		settings: settings, billing: billing, billingGateways: billingGateways,
		localRateLimits: newLocalRateLimiter(), trustedProxies: trustedProxies,
		htmxErrorsJS: htmxErrorsJS,
	}
	if cfg.Upload == nil || cfg.Upload.GuestEnabled {
		if cfg.RateLimit == nil || !cfg.RateLimit.Enabled {
			logger.Warn("guest uploads are enabled while API rate limiting is disabled; unauthenticated clients can create upload authorizations without a request limit")
		}
	}
	handler.emailSender, err = email.New(context.Background(), cfg.Email)
	if err != nil {
		return nil, fmt.Errorf("configure email: %w", err)
	}
	if cfg.Auth != nil {
		downloadSecret := sha256.Sum256([]byte("objectshare-download-form-v1\x00" + cfg.Auth.JWTSecret))
		handler.downloadSecret = downloadSecret[:]
	}
	if len(billingGateways) != 0 {
		if billing == nil {
			return nil, errors.New("enabled billing requires a billing repository")
		}
	}
	if userRepository != nil {
		if cfg.Auth == nil {
			return nil, errors.New("authentication configuration is required")
		}
		handler.jwt, err = appauth.NewJWTManager(cfg.Auth.JWTSecret, cfg.Auth.TokenLifetime.Duration())
		if err != nil {
			return nil, fmt.Errorf("configure JWT authentication: %w", err)
		}
		handler.settingsKey = cfg.SettingsKey
		oauthSecret := sha256.Sum256([]byte("objectshare-oauth-flow-v1\x00" + cfg.Auth.JWTSecret))
		handler.oauthSecret = oauthSecret[:]
		handler.oauthProviders = appauth.NewOAuthProviders(cfg.Auth.OAuth)
	}
	// Objects stored while encryption was on stay readable after an
	// administrator turns it off for new uploads, as long as the key remains.
	if cfg.Encryption != nil && cfg.Encryption.Key != "" {
		key, err := config.DecodeEncryptionKey(cfg.Encryption.Key)
		if err == nil {
			handler.readCipher, err = appcrypto.New(key)
		}
		if err != nil && cfg.Encryption.Enabled {
			return nil, err
		} else if err != nil {
			logger.Warn("the stored encryption key is invalid; existing server-side encrypted files cannot be downloaded", "error", err)
		} else {
			handler.cipherSlot = make(chan struct{}, 1)
		}
	}
	if cfg.Encryption != nil && cfg.Encryption.Enabled {
		if handler.readCipher == nil {
			_, err := config.DecodeEncryptionKey(cfg.Encryption.Key)
			return nil, err
		}
		handler.cipher = handler.readCipher
	} else {
		handler.direct, _ = storage.(service.DirectUploader)
		if handler.direct != nil {
			handler.directPolicy = handler.direct.DirectUploadPolicy()
			if handler.directPolicy.Expires <= 0 || handler.directPolicy.MaxSize <= 0 {
				return nil, errors.New("object storage returned an invalid direct-upload policy")
			}
		}
	}
	return handler, nil
}

func (handler *Handler) Index(writer http.ResponseWriter, request *http.Request) {
	maxFileSize := handler.config.MaxFileSize
	if handler.direct != nil && maxFileSize*mebibyte > handler.directPolicy.MaxSize {
		maxFileSize = handler.directPolicy.MaxSize / mebibyte
	}
	settings := handler.uploadSettings()
	user := identityUser(request)
	canUpload := user != nil || settings.GuestEnabled
	if user != nil && user.EmailVerifiedAt == nil && handler.verificationSettings().RequireForUploads {
		canUpload = false
	}
	quotaLabel := handler.uploadQuotaLabel(request, user)
	signupEnabled := handler.config.Auth != nil && handler.config.Auth.SignupEnabled
	handler.render(writer, "index.html", struct {
		Version, QuotaLabel                    string
		MaxFileSize                            int64
		MaxFiles                               int
		DirectUpload, SignupEnabled, CanUpload bool
		User                                   *db.User
		CSRF                                   string
		Captcha                                *captchaWidget
	}{config.GetVersion(), quotaLabel, maxFileSize, settings.MaxFilesPerBatch, handler.direct != nil, signupEnabled, canUpload, user, identityCSRF(request), handler.captchaWidget("upload")})
}

func (handler *Handler) DirectUploadConnectSources() []string {
	return append([]string(nil), handler.directPolicy.ConnectSources...)
}

func (handler *Handler) UploadScript(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	writer.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeContent(writer, request, "upload.js", time.Time{}, bytes.NewReader(handler.uploadJS))
}

func (handler *Handler) SharingScript(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	writer.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeContent(writer, request, "sharing.js", time.Time{}, bytes.NewReader(handler.sharingJS))
}

func (handler *Handler) ThemeScript(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	writer.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeContent(writer, request, "theme.js", time.Time{}, bytes.NewReader(handler.themeJS))
}

func (handler *Handler) CaptchaScript(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	writer.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeContent(writer, request, "captcha.js", time.Time{}, bytes.NewReader(handler.captchaJS))
}

func (handler *Handler) AdminUsersScript(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	writer.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeContent(writer, request, "admin_users.js", time.Time{}, bytes.NewReader(handler.adminUsersJS))
}

func (handler *Handler) AdminUsersStyles(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "text/css; charset=utf-8")
	writer.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeContent(writer, request, "admin_users.css", time.Time{}, bytes.NewReader(handler.adminUsersCSS))
}

func (handler *Handler) FileView(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "private, no-store")
	fileID, ok := validFileID(request)
	if !ok {
		http.NotFound(writer, request)
		return
	}
	file, err := handler.repository.Get(request.Context(), fileID)
	if errors.Is(err, db.ErrNotFound) {
		http.NotFound(writer, request)
		return
	}
	if err != nil {
		handler.internalError(writer, request, "get file", err)
		return
	}
	if !handler.canReadFile(request, file) {
		http.NotFound(writer, request)
		return
	}
	canDirectLink := file.ClientEncryption == "" && !handler.captchaEnabled("download") && handler.fileHasDirectLinks(request.Context(), file)
	handler.render(writer, "file_view.html", struct {
		Version, FileID, FileName, FileSize, FileSHA256, FileSHA3, CreatedAt, UpdatedAt, DirectURL, ClientEncryption string
		CanManage, Encrypted, ChecksumsVerified, CanDirectLink                                                       bool
		SignupEnabled                                                                                                bool
		User                                                                                                         *db.User
		CSRF                                                                                                         string
		Captcha                                                                                                      *captchaWidget
		DownloadToken                                                                                                string
	}{
		Version: config.GetVersion(), FileID: file.FileID, FileName: file.FileName,
		FileSize: humanSize(file.FileSize), FileSHA256: file.FileSHA256, FileSHA3: file.FileSHA3,
		CreatedAt: file.CreatedAt.UTC().Format(time.RFC3339), UpdatedAt: file.UpdatedAt.UTC().Format(time.RFC3339),
		ClientEncryption: file.ClientEncryption, CanManage: handler.isOwner(request, file), Encrypted: file.IsEncrypted,
		ChecksumsVerified: file.ChecksumStatus == "verified",
		SignupEnabled:     handler.config.Auth != nil && handler.config.Auth.SignupEnabled,
		User:              identityUser(request), CSRF: identityCSRF(request), Captcha: handler.captchaWidget("download"),
		CanDirectLink: canDirectLink,
		DownloadToken: handler.downloadFormToken(file.FileID, time.Now().UTC().Add(10*time.Minute)),
		DirectURL:     handler.publicDownloadURL(file.FileID),
	})
}

func (handler *Handler) publicDownloadURL(fileID string) string {
	if handler.config.Billing != nil && handler.config.Billing.PublicURL != "" {
		return handler.config.Billing.PublicURL + "/api/v1/download/" + fileID
	}
	return "/api/v1/download/" + fileID
}

func (handler *Handler) Download(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "private, no-store")
	if !handler.allowRequest(writer, request, "download", handler.rateLimitSettings().DownloadLimit) {
		return
	}
	if handler.captchaEnabled("download") && request.Method != http.MethodPost {
		http.Error(writer, "CAPTCHA-protected downloads must use POST from the file page.", http.StatusMethodNotAllowed)
		return
	}
	if request.Method == http.MethodPost {
		request.Body = http.MaxBytesReader(writer, request.Body, 16*1024)
		if err := request.ParseForm(); err != nil {
			http.Error(writer, "Invalid download request.", http.StatusBadRequest)
			return
		}
		if !handler.verifyCaptcha(writer, request, "download", "") {
			return
		}
	}
	fileID, ok := validFileID(request)
	if !ok {
		http.NotFound(writer, request)
		return
	}
	file, err := handler.repository.Get(request.Context(), fileID)
	if errors.Is(err, db.ErrNotFound) {
		http.NotFound(writer, request)
		return
	}
	if err != nil {
		handler.internalError(writer, request, "get file", err)
		return
	}
	if !handler.canReadFile(request, file) {
		http.NotFound(writer, request)
		return
	}
	if request.Method == http.MethodGet {
		if !handler.fileHasDirectLinks(request.Context(), file) && !handler.isOwner(request, file) {
			http.Redirect(writer, request, "/file/"+file.FileID, http.StatusSeeOther)
			return
		}
	} else if handler.billing != nil && !handler.validDownloadFormToken(file.FileID, request.FormValue("download_token"), time.Now().UTC()) {
		http.Error(writer, "Open the file details page before downloading.", http.StatusForbidden)
		return
	}
	if file.ClientEncryption == "" && !file.IsEncrypted && fileShareMode(file) == db.ShareLink && handler.fileModeration(request, file) == db.ModerationNone {
		if location, err := handler.storage.PresignGet(request.Context(), fileID, file.FileName); err == nil {
			status := http.StatusTemporaryRedirect
			if request.Method == http.MethodPost {
				// CAPTCHA-protected downloads arrive as POST. A 303 changes the
				// subsequent presigned object-storage request back to GET.
				status = http.StatusSeeOther
			}
			http.Redirect(writer, request, location, status)
			return
		} else if !errors.Is(err, service.ErrPresignUnsupported) {
			handler.internalError(writer, request, "presign download", err)
			return
		}
	}

	body, err := handler.storage.Open(request.Context(), fileID)
	if err != nil {
		handler.internalError(writer, request, "open object", err)
		return
	}
	defer body.Close()
	writer = handler.withDownloadProgress(writer)
	writer.Header().Set("Content-Type", file.ContentType)
	downloadName := file.FileName
	if file.ClientEncryption != "" {
		downloadName += ".objectshare"
		writer.Header().Set("Content-Type", "application/octet-stream")
	}
	writer.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": downloadName}))
	writer.Header().Set("Cache-Control", "private, no-store")
	if file.IsEncrypted {
		if handler.readCipher == nil {
			handler.internalError(writer, request, "decrypt object", errors.New("encryption key is unavailable"))
			return
		}
		plaintext, err := handler.decryptObject(body, file)
		switch {
		case errors.Is(err, errCipherBusy):
			http.Error(writer, "Encryption capacity is busy; retry shortly.", http.StatusServiceUnavailable)
			return
		case err != nil:
			handler.internalError(writer, request, "decrypt object", err)
			return
		}
		writer.Header().Set("Content-Length", fmt.Sprint(len(plaintext)))
		handler.logStreamError(request, fileID, "stream decrypted download", func() error {
			_, err := io.Copy(writer, bytes.NewReader(plaintext))
			return err
		})
		return
	}
	writer.Header().Set("Content-Length", fmt.Sprint(file.FileSize))
	handler.logStreamError(request, fileID, "stream download", func() error {
		_, err := io.Copy(writer, body)
		return err
	})
}

// logStreamError runs a response-body copy and logs why it stopped early. A
// client that disconnects mid-download (its request context is cancelled) is
// routine and stays quiet; a storage read failure or another write error is not.
func (handler *Handler) logStreamError(request *http.Request, fileID, operation string, copyBody func() error) {
	if err := copyBody(); err != nil && request.Context().Err() == nil {
		handler.logger.Warn(operation+" ended early", "file_id", fileID, "error", err)
	}
}

// decryptObject reads and decrypts a stored object while holding the cipher
// slot, releasing it before the caller streams the plaintext to a possibly slow
// client so one slow download cannot block every other encrypted transfer.
//
// The read is bounded by the size recorded when the file was stored, not by the
// current max_file_size: lowering that setting must not strand older files.
func (handler *Handler) decryptObject(body io.Reader, file *db.FileList) ([]byte, error) {
	if !handler.acquireCipherSlot() {
		return nil, errCipherBusy
	}
	defer handler.releaseCipherSlot()
	limit := min(max(file.FileSize, 0), config.MaxEncryptedFileSizeMiB*mebibyte) + int64(handler.readCipher.Overhead()) + 1
	ciphertext, err := io.ReadAll(io.LimitReader(body, limit))
	if err != nil || int64(len(ciphertext)) >= limit {
		return nil, fmt.Errorf("read encrypted object: %w", errors.Join(err, errors.New("object exceeds the encrypted size limit")))
	}
	return handler.readCipher.DecryptFor(file.FileID, ciphertext)
}

func (handler *Handler) fileHasDirectLinks(ctx context.Context, file *db.FileList) bool {
	if handler.billing == nil {
		return true
	}
	if file.FileOwner == nil {
		return false
	}
	entitlements, err := handler.billing.Entitlements(ctx, *file.FileOwner, time.Now().UTC())
	if err != nil {
		handler.logger.Warn("check direct-link entitlement", "user_id", *file.FileOwner, "error", err)
		return false
	}
	return entitlements.Active && entitlements.DirectLinks
}

func (handler *Handler) downloadFormToken(fileID string, expires time.Time) string {
	expiry := strconv.FormatInt(expires.Unix(), 10)
	mac := hmac.New(sha256.New, handler.downloadSecret)
	_, _ = mac.Write([]byte(fileID + "\x00" + expiry))
	return expiry + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (handler *Handler) validDownloadFormToken(fileID, token string, now time.Time) bool {
	expiryText, signature, ok := strings.Cut(token, ".")
	if !ok || signature == "" {
		return false
	}
	expiry, err := strconv.ParseInt(expiryText, 10, 64)
	if err != nil || now.After(time.Unix(expiry, 0)) || time.Unix(expiry, 0).After(now.Add(15*time.Minute)) {
		return false
	}
	want := handler.downloadFormToken(fileID, time.Unix(expiry, 0))
	return subtle.ConstantTimeCompare([]byte(want), []byte(token)) == 1
}

func (handler *Handler) Delete(writer http.ResponseWriter, request *http.Request) {
	if !handler.verifyAuthenticatedMutationCSRF(writer, request) {
		return
	}
	fileID, ok := validFileID(request)
	if !ok {
		http.NotFound(writer, request)
		return
	}
	file, err := handler.repository.Get(request.Context(), fileID)
	if errors.Is(err, db.ErrNotFound) {
		http.NotFound(writer, request)
		return
	}
	if err != nil {
		handler.internalError(writer, request, "get file", err)
		return
	}
	if file.UploadStatus != "complete" {
		http.NotFound(writer, request)
		return
	}
	if !handler.isOwner(request, file) {
		http.Error(writer, "Forbidden", http.StatusForbidden)
		return
	}
	// Claim first when the repository supports it, so a failure after the object
	// is gone leaves a "deleting" row the retention sweep retries rather than a
	// "complete" record pointing at a missing object.
	claimer, claimed := handler.repository.(db.FileDeletionClaimer)
	if claimed {
		if err := claimer.ClaimFileDeletion(request.Context(), fileID, time.Now().UTC()); err != nil {
			if errors.Is(err, db.ErrNotFound) {
				http.NotFound(writer, request)
				return
			}
			handler.internalError(writer, request, "claim file deletion", err)
			return
		}
	}
	if err := handler.storage.Delete(request.Context(), fileID); err != nil {
		if claimed {
			if releaseErr := claimer.ReleaseRetentionClaim(context.WithoutCancel(request.Context()), fileID); releaseErr != nil && !errors.Is(releaseErr, db.ErrNotFound) {
				handler.logger.Error("release file deletion claim", "file_id", fileID, "error", releaseErr)
			}
		}
		handler.internalError(writer, request, "delete object", err)
		return
	}
	if err := handler.repository.Delete(request.Context(), fileID); err != nil && !errors.Is(err, db.ErrNotFound) {
		handler.logger.Error("delete file record after removing its object; the retention sweep will retry", "file_id", fileID, "claimed", claimed, "error", err)
		handler.internalError(writer, request, "delete file record", err)
		return
	}
	http.SetCookie(writer, ownerCookie(fileID, "", handler.config.SecureCookies, -time.Hour))
	handler.redirect(writer, request, "/")
}

func (handler *Handler) Update(writer http.ResponseWriter, request *http.Request) {
	if !handler.verifyAuthenticatedMutationCSRF(writer, request) {
		return
	}
	fileID, ok := validFileID(request)
	if !ok {
		http.NotFound(writer, request)
		return
	}
	file, err := handler.repository.Get(request.Context(), fileID)
	if errors.Is(err, db.ErrNotFound) {
		http.NotFound(writer, request)
		return
	}
	if err != nil {
		handler.internalError(writer, request, "get file", err)
		return
	}
	if file.UploadStatus != "complete" {
		http.NotFound(writer, request)
		return
	}
	if !handler.isOwner(request, file) {
		http.Error(writer, "Forbidden", http.StatusForbidden)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 4096)
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "Invalid form.", http.StatusBadRequest)
		return
	}
	name, err := safeFileName(request.FormValue("name"))
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	if err := handler.repository.Rename(request.Context(), fileID, name); err != nil {
		handler.internalError(writer, request, "rename file", err)
		return
	}
	handler.redirect(writer, request, "/file/"+fileID)
}

func (handler *Handler) Live(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(writer, `{"status":"ok"}`)
}

func (handler *Handler) Ready(writer http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
	defer cancel()
	if err := handler.repository.Ping(ctx); err != nil {
		http.Error(writer, "not ready", http.StatusServiceUnavailable)
		return
	}
	handler.Live(writer, request)
}

func (handler *Handler) render(writer http.ResponseWriter, name string, data any) {
	handler.renderStatus(writer, http.StatusOK, name, data)
}

// Render before committing headers so a template failure cannot masquerade as
// a successful, partially rendered page (including pages containing forms).
func (handler *Handler) renderStatus(writer http.ResponseWriter, status int, name string, data any) {
	writer.Header().Set("Cache-Control", "private, no-store")
	var page bytes.Buffer
	if err := handler.templates.ExecuteTemplate(&page, name, data); err != nil {
		handler.logger.Error("render template", "template", name, "error", err)
		http.Error(writer, "This page could not be displayed. Please try again.", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(status)
	_, _ = writer.Write(page.Bytes())
}

func (handler *Handler) internalError(writer http.ResponseWriter, request *http.Request, operation string, err error) {
	if err == nil {
		err = errors.New("unexpected empty error")
	}
	handler.logger.Error(operation, "request_id", middleware.GetReqID(request.Context()), "error", err)
	http.Error(writer, "Internal server error.", http.StatusInternalServerError)
}

func (handler *Handler) redirect(writer http.ResponseWriter, request *http.Request, location string) {
	if request.Header.Get("HX-Request") == "true" {
		writer.Header().Set("HX-Redirect", location)
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(writer, request, location, http.StatusSeeOther)
}

func (handler *Handler) isOwner(request *http.Request, file *db.FileList) bool {
	switch handler.fileModeration(request, file) {
	case db.ModerationShadowbanned:
		return signedInFileOwner(request, file)
	case db.ModerationNone:
	default:
		return false
	}
	if file.FileOwner != nil {
		return signedInFileOwner(request, file)
	}
	cookie, err := request.Cookie(ownerCookieName(file.FileID))
	if err != nil {
		return false
	}
	return ownerTokenMatches(file, cookie.Value)
}

func identityUser(request *http.Request) *db.User {
	if identity := currentIdentity(request); identity != nil {
		return identity.User
	}
	return nil
}

func identityCSRF(request *http.Request) string {
	if identity := currentIdentity(request); identity != nil {
		return identity.Claims.CSRF
	}
	return ""
}

func (handler *Handler) uploadSettings() config.UploadConfig {
	if handler.config.Upload == nil {
		return config.UploadConfig{GuestEnabled: true, MaxFilesPerBatch: 10, MaxPendingGuestMiB: config.DefaultMaxPendingGuestMiB}
	}
	settings := *handler.config.Upload
	if settings.MaxFilesPerBatch == 0 {
		settings.MaxFilesPerBatch = 10
	}
	if settings.MaxPendingGuestMiB == 0 {
		settings.MaxPendingGuestMiB = config.DefaultMaxPendingGuestMiB
	}
	return settings
}

func (handler *Handler) uploadQuotaLabel(request *http.Request, user *db.User) string {
	if user == nil {
		if !handler.uploadSettings().GuestEnabled {
			return "Guest uploads are disabled."
		}
		if handler.config.Retention != nil && handler.config.Retention.GuestDays > 0 {
			return retentionNotice("Guest files", handler.config.Retention.GuestDays)
		}
		return ""
	}
	labels := make([]string, 0, 2)
	usage, err := handler.repository.UploadUsage(request.Context(), user.ID)
	if err != nil {
		handler.logger.Warn("load upload quota usage", "error", err)
		labels = append(labels, "Upload quota is enforced when the upload begins.")
	} else if usage.Limit == 0 {
		labels = append(labels, "Account storage quota: unlimited.")
	} else {
		labels = append(labels, fmt.Sprintf("Account storage: %s used of %s.", humanSize(usage.Used), humanSize(usage.Limit)))
	}
	if !user.IsPaid && handler.config.Retention != nil && handler.config.Retention.UnpaidDays > 0 {
		labels = append(labels, retentionNotice("Files on unpaid accounts", handler.config.Retention.UnpaidDays))
	}
	return strings.Join(labels, " ")
}

func retentionNotice(subject string, days int) string {
	unit := "days"
	if days == 1 {
		unit = "day"
	}
	return fmt.Sprintf("%s are automatically deleted %d %s after upload.", subject, days, unit)
}

func ownerTokenMatches(file *db.FileList, token string) bool {
	hash := sha256.Sum256([]byte(token))
	want, err := hex.DecodeString(file.AnonymousSessionToken)
	return err == nil && len(want) == len(hash) && subtle.ConstantTimeCompare(hash[:], want) == 1
}

func validFileID(request *http.Request) (string, bool) {
	value := chi.URLParam(request, "id")
	parsed, err := uuid.Parse(value)
	return value, err == nil && parsed.String() == strings.ToLower(value)
}

func newOwnerToken() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(hash[:]), nil
}

func ownerCookieName(fileID string) string {
	return "objectshare_owner_" + strings.ReplaceAll(fileID, "-", "")
}

func ownerCookie(fileID, token string, secure bool, lifetime time.Duration) *http.Cookie {
	return &http.Cookie{Name: ownerCookieName(fileID), Value: token, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: int(lifetime.Seconds())}
}

func humanSize(size int64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	value := float64(size)
	unit := 0
	for value >= 1024 && unit < len(units)-1 {
		value /= 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d %s", size, units[unit])
	}
	return fmt.Sprintf("%.1f %s", value, units[unit])
}

type byteCounter struct{ total int64 }

func (counter *byteCounter) Write(buffer []byte) (int, error) {
	counter.total += int64(len(buffer))
	return len(buffer), nil
}

func (handler *Handler) acquireCipherSlot() bool {
	select {
	case handler.cipherSlot <- struct{}{}:
		return true
	default:
		return false
	}
}

func (handler *Handler) releaseCipherSlot() { <-handler.cipherSlot }

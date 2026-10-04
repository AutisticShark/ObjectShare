package api

import (
	"context"
	"crypto/rand"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AutisticShark/ObjectShare/api/htmx"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func Router(handler *htmx.Handler, logger *slog.Logger) http.Handler {
	requireSameOrigin := sameOrigin(handler.RequestScheme, logger)
	router := chi.NewRouter()
	router.Use(requestID)
	router.Use(requestIDHeader)
	router.Use(accessLog(logger))
	router.Use(serveHeadAsGet)
	router.Use(middleware.Recoverer)
	router.Use(securityHeaders(handler.CaptchaCSPEnabled(), handler.BrandingImageSources(), handler.DirectUploadConnectSources()...))
	router.Use(handler.Authenticate)

	router.Get("/assets/branding.css", handler.BrandingStyles)
	router.Get("/assets/theme.js", handler.ThemeScript)
	router.Get("/assets/upload.js", handler.UploadScript)
	router.Get("/assets/client-encryption.js", handler.ClientEncryptionScript)
	router.Get("/assets/sharing.js", handler.SharingScript)
	router.Get("/assets/captcha.js", handler.CaptchaScript)
	router.Get("/assets/admin-users.js", handler.AdminUsersScript)
	router.Get("/assets/admin-users.css", handler.AdminUsersStyles)
	router.Get("/assets/htmx-errors.js", handler.HTMXErrorsScript)
	router.Get("/health/live", handler.Live)
	router.Get("/health/ready", handler.Ready)
	router.Get("/setup", handler.SetupPage)
	router.With(requireSameOrigin).Post("/setup", handler.Setup)

	router.Group(func(router chi.Router) {
		router.Use(handler.SetupComplete)
		router.Get("/", handler.Index)
		router.Get("/file/{id}", handler.FileView)
		router.Get("/file/{id}/sharing", handler.SharingPage)
		router.With(requireSameOrigin).Post("/file/{id}/sharing", handler.UpdateSharing)
		router.Get("/uploads/complete", handler.UploadResults)
		router.Get("/plans", handler.Plans)
		router.Post("/api/v1/billing/{gateway}/webhook", handler.BillingWebhook)
		router.With(getOnly).Get("/billing/paypal/topup/return", handler.PayPalTopUpReturn)
		router.Get("/login", handler.LoginPage)
		router.Get("/login/mfa", handler.MFAChallenge)
		router.With(requireSameOrigin).Post("/login/mfa", handler.VerifyMFA)
		router.With(requireSameOrigin).Post("/login/mfa/resend", handler.ResendMFA)
		router.With(handler.RequireUser).Get("/account/mfa", handler.MFASettings)
		router.With(handler.RequireUser, requireSameOrigin).Post("/account/mfa", handler.BeginMFAChange)
		router.With(requireSameOrigin).Post("/login", handler.Login)
		router.Get("/oauth/{provider}/start", handler.OAuthStart)
		router.With(requireSameOrigin).Post("/oauth/{provider}/start", handler.OAuthStart)
		router.With(getOnly).Get("/oauth/{provider}/callback", handler.OAuthCallback)
		router.Get("/signup", handler.SignupPage)
		router.Get("/verify-email", handler.VerifyEmailPage)
		router.With(requireSameOrigin).Post("/verify-email", handler.VerifyEmail)
		router.With(handler.RequireUser, requireSameOrigin).Post("/account/email/resend", handler.ResendVerification)
		router.With(requireSameOrigin).Post("/signup", handler.Signup)
		router.With(handler.RequireUser, requireSameOrigin).Post("/logout", handler.Logout)
		router.With(handler.RequireUser).Get("/account", handler.Account)
		router.With(handler.RequireUser).Get("/account/encryption", handler.ClientKey)
		router.With(handler.RequireUser, requireSameOrigin).Post("/account/encryption", handler.ClientKey)
		router.With(handler.RequireUser).Get("/invoices", handler.Invoices)
		router.With(handler.RequireUser).Get("/invoices/{id}", handler.Invoice)
		router.With(handler.RequireUser).Get("/invoices/{id}/pdf", handler.InvoicePDF)
		router.With(handler.RequireUser, requireSameOrigin).Post("/billing/invoices/{id}", handler.CreateInvoice)
		router.With(handler.RequireUser, requireSameOrigin).Post("/invoices/{id}/pay", handler.PayInvoice)
		router.With(handler.RequireUser, requireSameOrigin).Post("/billing/checkout/{id}", handler.BillingCheckout)
		router.With(handler.RequireUser, requireSameOrigin).Post("/billing/topup/{gateway}", handler.BillingTopUp)
		router.With(handler.RequireUser, requireSameOrigin).Post("/billing/credit/{id}", handler.BillingPurchaseWithCredit)
		router.With(handler.RequireUser, requireSameOrigin).Post("/billing/portal", handler.BillingPortal)
		router.With(handler.RequireUser, requireSameOrigin).Post("/account/profile", handler.UpdateProfile)
		router.With(handler.RequireUser, requireSameOrigin).Post("/account/theme", handler.UpdateTheme)
		router.With(handler.RequireUser, requireSameOrigin).Post("/account/password", handler.UpdateOwnPassword)
		router.With(handler.RequireUser, requireSameOrigin).Post("/account/oauth/{provider}/unlink", handler.OAuthUnlink)
		router.With(handler.RequireAdmin).Get("/admin/users", handler.AdminUsers)
		router.With(handler.RequireUser).Get("/files", handler.Files)
		router.With(handler.RequireUser).Get("/billing", handler.BillingOverview)
		router.With(handler.RequireAdmin).Get("/admin", handler.AdminDashboard)
		router.With(handler.RequireAdmin).Get("/admin/invoices", handler.AdminInvoiceList)
		router.With(handler.RequireAdmin).Get("/admin/settings", handler.AdminSettings)
		router.With(handler.RequireAdmin).Get("/admin/plans", handler.AdminPlans)
		router.With(handler.RequireAdmin, requireSameOrigin).Post("/admin/plans", handler.AdminSavePlan)
		router.With(handler.RequireAdmin, requireSameOrigin).Post("/admin/plans/{id}", handler.AdminSavePlan)
		router.With(handler.RequireAdmin, requireSameOrigin).Post("/admin/settings", handler.AdminSaveSettings)
		router.With(handler.RequireAdmin, requireSameOrigin).Post("/admin/settings/email/test", handler.AdminTestEmail)
		router.With(handler.RequireAdmin, requireSameOrigin).Post("/admin/users", handler.AdminCreateUser)
		router.With(handler.RequireAdmin, requireSameOrigin).Post("/admin/users/{id}/access", handler.AdminUpdateAccess)
		router.With(handler.RequireAdmin, requireSameOrigin).Post("/admin/users/{id}/moderation", handler.AdminModerateUser)
		router.With(handler.RequireAdmin, requireSameOrigin).Post("/admin/users/{id}/quota", handler.AdminUpdateUploadQuota)
		router.With(handler.RequireAdmin, requireSameOrigin).Post("/admin/users/{id}/paid", handler.AdminUpdatePaidStatus)
		router.With(handler.RequireAdmin, requireSameOrigin).Post("/admin/users/{id}/credit", handler.AdminAdjustCredit)
		router.With(handler.RequireAdmin, requireSameOrigin).Post("/admin/users/{id}/password", handler.AdminResetPassword)
		router.With(handler.RequireAdmin, requireSameOrigin).Post("/admin/users/{id}/delete", handler.AdminDeleteUser)

		router.Route("/api/v1", func(router chi.Router) {
			router.Use(handler.RateLimitAPI)
			router.With(requireSameOrigin).Post("/auth/login", handler.APILogin)
			router.With(requireSameOrigin).Post("/auth/mfa", handler.APIVerifyMFA)
			router.With(requireSameOrigin).Post("/auth/mfa/resend", handler.APIResendMFA)
			router.With(handler.RequireUser, requireSameOrigin).Post("/auth/logout", handler.APILogout)
			router.With(requireSameOrigin).Post("/upload", handler.Upload)
			router.With(requireSameOrigin).Post("/uploads/direct", handler.BeginDirectUpload)
			router.With(requireSameOrigin).Post("/uploads/direct/batch", handler.BeginDirectUploadBatch)
			router.With(requireSameOrigin).Post("/uploads/direct/{id}/complete", handler.CompleteDirectUpload)
			router.With(requireSameOrigin).Post("/uploads/direct/{id}/abort", handler.AbortDirectUpload)
			router.With(getOnly).Get("/download/{id}", handler.Download)
			router.With(requireSameOrigin).Post("/download/{id}", handler.Download)
			router.With(requireSameOrigin).Post("/delete/{id}", handler.Delete)
			router.With(requireSameOrigin).Delete("/delete/{id}", handler.Delete)
			router.With(requireSameOrigin).Post("/update/{id}", handler.Update)
			router.With(requireSameOrigin).Put("/update/{id}", handler.Update)
		})
	})
	return router
}

// requestID gives every request a random server-generated ID under chi's
// request-ID context key. A client-supplied X-Request-Id is never adopted: it
// could forge or collide with another request's log entries. chi's generator
// is not used because it embeds the hostname (the container ID).
func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		ctx := context.WithValue(request.Context(), middleware.RequestIDKey, rand.Text())
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

// upstreamRequestID returns a proxy's X-Request-Id when it is a plain token,
// so access logs can still be correlated with proxy logs without trusting it.
func upstreamRequestID(request *http.Request) string {
	value := request.Header.Get("X-Request-Id")
	if value == "" || len(value) > 128 {
		return ""
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("-_.:", character)) {
			return ""
		}
	}
	return value
}

type headRequestKey struct{}

// serveHeadAsGet answers HEAD with the matching GET route. The handler sees a
// GET request, so method checks inside handlers keep their GET meaning (they
// treat any other method as a form submission); net/http discards the body
// because the connection's request is still HEAD. Routes without GET answer
// 405, so HEAD never reaches a POST handler.
func serveHeadAsGet(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodHead {
			request = request.WithContext(context.WithValue(request.Context(), headRequestKey{}, true))
			request.Method = http.MethodGet
		}
		next.ServeHTTP(writer, request)
	})
}

// getOnly keeps HEAD away from GET routes that change state (payment capture,
// OAuth login) or stream a whole object only for its body to be discarded.
func getOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if head, _ := request.Context().Value(headRequestKey{}).(bool); head {
			writer.Header().Set("Allow", http.MethodGet)
			http.Error(writer, "Method not allowed.", http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

// requestIDHeader echoes the request ID that access and error logs record, so a
// user or proxy can quote it when reporting a failure.
func requestIDHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if id := middleware.GetReqID(request.Context()); id != "" {
			writer.Header().Set("X-Request-Id", id)
		}
		next.ServeHTTP(writer, request)
	})
}

func accessLog(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			wrapped := middleware.NewWrapResponseWriter(writer, request.ProtoMajor)
			start := time.Now()
			next.ServeHTTP(wrapped, request)
			attributes := []any{"request_id", middleware.GetReqID(request.Context()), "method", request.Method,
				"path", request.URL.Path, "status", wrapped.Status(), "bytes", wrapped.BytesWritten(), "duration_ms", time.Since(start).Milliseconds()}
			if upstream := upstreamRequestID(request); upstream != "" {
				attributes = append(attributes, "upstream_request_id", upstream)
			}
			logger.Info("http request", attributes...)
		})
	}
}

func securityHeaders(captchaEnabled bool, imageSources []string, connectSources ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			imageSource := "'self' data:"
			if len(imageSources) > 0 {
				imageSource += " " + strings.Join(imageSources, " ")
			}
			connectSource := "'self'"
			if len(connectSources) > 0 {
				connectSource += " " + strings.Join(connectSources, " ")
			}
			scriptSource := "'self' https://cdn.jsdelivr.net"
			frameSource := "'none'"
			if captchaEnabled {
				scriptSource += " https://challenges.cloudflare.com"
				connectSource += " https://challenges.cloudflare.com"
				frameSource = "https://challenges.cloudflare.com"
			}
			writer.Header().Set("Content-Security-Policy", "default-src 'none'; script-src "+scriptSource+"; connect-src "+connectSource+"; frame-src "+frameSource+"; style-src 'self' https://cdn.jsdelivr.net; font-src https://cdn.jsdelivr.net; img-src "+imageSource+"; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
			writer.Header().Set("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
			writer.Header().Set("Referrer-Policy", "no-referrer")
			writer.Header().Set("X-Content-Type-Options", "nosniff")
			writer.Header().Set("X-Frame-Options", "DENY")
			next.ServeHTTP(writer, request)
		})
	}
}

// sameOrigin rejects state-changing browser requests from another origin. The
// Origin host must match Host and, when requestScheme can determine it
// reliably, the Origin scheme must match the scheme the browser used.
func sameOrigin(requestScheme func(*http.Request) string, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			site := request.Header.Get("Sec-Fetch-Site")
			if site != "" && site != "same-origin" {
				http.Error(writer, "Cross-site request rejected.", http.StatusForbidden)
				return
			}
			if origin := request.Header.Get("Origin"); origin != "" {
				parsed, err := url.Parse(origin)
				if err != nil {
					http.Error(writer, "Cross-site request rejected.", http.StatusForbidden)
					return
				}
				if !strings.EqualFold(parsed.Host, request.Host) {
					// Cross-site browser requests were rejected above by
					// Sec-Fetch-Site. A browser that reports a same-origin request
					// (or an older one that omits the header) yet names another
					// host is usually behind a reverse proxy that rewrote Host.
					if parsed.Host != "" {
						logger.Warn("rejected a request whose Origin host differs from the Host header; a reverse proxy must forward the browser's Host header (nginx: proxy_set_header Host $host;)",
							"request_id", middleware.GetReqID(request.Context()), "origin_host", parsed.Host, "host", request.Host, "path", request.URL.Path)
					}
					http.Error(writer, "Cross-site request rejected.", http.StatusForbidden)
					return
				}
				if scheme := requestScheme(request); scheme != "" && !strings.EqualFold(parsed.Scheme, scheme) {
					logger.Warn("rejected a request whose Origin scheme differs from the request scheme; a trusted reverse proxy must send the browser-facing scheme in X-Forwarded-Proto",
						"request_id", middleware.GetReqID(request.Context()), "origin_scheme", parsed.Scheme, "scheme", scheme, "path", request.URL.Path)
					http.Error(writer, "Cross-site request rejected.", http.StatusForbidden)
					return
				}
			}
			next.ServeHTTP(writer, request)
		})
	}
}

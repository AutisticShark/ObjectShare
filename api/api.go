package api

import (
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
	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(accessLog(logger))
	router.Use(middleware.Recoverer)
	router.Use(securityHeaders(handler.CaptchaCSPEnabled(), handler.DirectUploadConnectSources()...))
	router.Use(handler.Authenticate)

	router.Get("/assets/theme.js", handler.ThemeScript)
	router.Get("/assets/upload.js", handler.UploadScript)
	router.Get("/assets/captcha.js", handler.CaptchaScript)
	router.Get("/assets/admin-users.js", handler.AdminUsersScript)
	router.Get("/assets/admin-users.css", handler.AdminUsersStyles)
	router.Get("/health/live", handler.Live)
	router.Get("/health/ready", handler.Ready)
	router.Get("/setup", handler.SetupPage)
	router.With(requireSameOrigin).Post("/setup", handler.Setup)

	router.Group(func(router chi.Router) {
		router.Use(handler.SetupComplete)
		router.Get("/", handler.Index)
		router.Get("/file/{id}", handler.FileView)
		router.Get("/uploads/complete", handler.UploadResults)
		router.Get("/plans", handler.Plans)
		router.Post("/api/v1/billing/{gateway}/webhook", handler.BillingWebhook)
		router.Get("/billing/paypal/topup/return", handler.PayPalTopUpReturn)
		router.Get("/login", handler.LoginPage)
		router.With(requireSameOrigin).Post("/login", handler.Login)
		router.Get("/oauth/{provider}/start", handler.OAuthStart)
		router.With(requireSameOrigin).Post("/oauth/{provider}/start", handler.OAuthStart)
		router.Get("/oauth/{provider}/callback", handler.OAuthCallback)
		router.Get("/signup", handler.SignupPage)
		router.With(requireSameOrigin).Post("/signup", handler.Signup)
		router.With(handler.RequireUser, requireSameOrigin).Post("/logout", handler.Logout)
		router.With(handler.RequireUser).Get("/account", handler.Account)
		router.With(handler.RequireUser, requireSameOrigin).Post("/billing/checkout/{id}", handler.BillingCheckout)
		router.With(handler.RequireUser, requireSameOrigin).Post("/billing/topup/{gateway}", handler.BillingTopUp)
		router.With(handler.RequireUser, requireSameOrigin).Post("/billing/credit/{id}", handler.BillingPurchaseWithCredit)
		router.With(handler.RequireUser, requireSameOrigin).Post("/billing/portal", handler.BillingPortal)
		router.With(handler.RequireUser, requireSameOrigin).Post("/account/profile", handler.UpdateProfile)
		router.With(handler.RequireUser, requireSameOrigin).Post("/account/theme", handler.UpdateTheme)
		router.With(handler.RequireUser, requireSameOrigin).Post("/account/password", handler.UpdateOwnPassword)
		router.With(handler.RequireUser, requireSameOrigin).Post("/account/oauth/{provider}/unlink", handler.OAuthUnlink)
		router.With(handler.RequireAdmin).Get("/admin/users", handler.AdminUsers)
		router.With(handler.RequireAdmin).Get("/admin/settings", handler.AdminSettings)
		router.With(handler.RequireAdmin).Get("/admin/plans", handler.AdminPlans)
		router.With(handler.RequireAdmin, requireSameOrigin).Post("/admin/plans", handler.AdminSavePlan)
		router.With(handler.RequireAdmin, requireSameOrigin).Post("/admin/plans/{id}", handler.AdminSavePlan)
		router.With(handler.RequireAdmin, requireSameOrigin).Post("/admin/settings", handler.AdminSaveSettings)
		router.With(handler.RequireAdmin, requireSameOrigin).Post("/admin/users", handler.AdminCreateUser)
		router.With(handler.RequireAdmin, requireSameOrigin).Post("/admin/users/{id}/access", handler.AdminUpdateAccess)
		router.With(handler.RequireAdmin, requireSameOrigin).Post("/admin/users/{id}/quota", handler.AdminUpdateUploadQuota)
		router.With(handler.RequireAdmin, requireSameOrigin).Post("/admin/users/{id}/paid", handler.AdminUpdatePaidStatus)
		router.With(handler.RequireAdmin, requireSameOrigin).Post("/admin/users/{id}/credit", handler.AdminAdjustCredit)
		router.With(handler.RequireAdmin, requireSameOrigin).Post("/admin/users/{id}/password", handler.AdminResetPassword)
		router.With(handler.RequireAdmin, requireSameOrigin).Post("/admin/users/{id}/delete", handler.AdminDeleteUser)

		router.Route("/api/v1", func(router chi.Router) {
			router.Use(handler.RateLimitAPI)
			router.With(requireSameOrigin).Post("/auth/login", handler.APILogin)
			router.With(handler.RequireUser, requireSameOrigin).Post("/auth/logout", handler.APILogout)
			router.With(requireSameOrigin).Post("/upload", handler.Upload)
			router.With(requireSameOrigin).Post("/uploads/direct", handler.BeginDirectUpload)
			router.With(requireSameOrigin).Post("/uploads/direct/batch", handler.BeginDirectUploadBatch)
			router.With(requireSameOrigin).Post("/uploads/direct/{id}/complete", handler.CompleteDirectUpload)
			router.With(requireSameOrigin).Post("/uploads/direct/{id}/abort", handler.AbortDirectUpload)
			router.Get("/download/{id}", handler.Download)
			router.With(requireSameOrigin).Post("/download/{id}", handler.Download)
			router.With(requireSameOrigin).Post("/delete/{id}", handler.Delete)
			router.With(requireSameOrigin).Delete("/delete/{id}", handler.Delete)
			router.With(requireSameOrigin).Post("/update/{id}", handler.Update)
			router.With(requireSameOrigin).Put("/update/{id}", handler.Update)
		})
	})
	return router
}

func accessLog(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			wrapped := middleware.NewWrapResponseWriter(writer, request.ProtoMajor)
			start := time.Now()
			next.ServeHTTP(wrapped, request)
			logger.Info("http request", "request_id", middleware.GetReqID(request.Context()), "method", request.Method,
				"path", request.URL.Path, "status", wrapped.Status(), "bytes", wrapped.BytesWritten(), "duration_ms", time.Since(start).Milliseconds())
		})
	}
}

func securityHeaders(captchaEnabled bool, connectSources ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
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
			writer.Header().Set("Content-Security-Policy", "default-src 'none'; script-src "+scriptSource+"; connect-src "+connectSource+"; frame-src "+frameSource+"; style-src 'self' https://cdn.jsdelivr.net; font-src https://cdn.jsdelivr.net; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
			writer.Header().Set("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
			writer.Header().Set("Referrer-Policy", "no-referrer")
			writer.Header().Set("X-Content-Type-Options", "nosniff")
			writer.Header().Set("X-Frame-Options", "DENY")
			next.ServeHTTP(writer, request)
		})
	}
}

func requireSameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if site := request.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
			http.Error(writer, "Cross-site request rejected.", http.StatusForbidden)
			return
		}
		if origin := request.Header.Get("Origin"); origin != "" {
			parsed, err := url.Parse(origin)
			if err != nil || !strings.EqualFold(parsed.Host, request.Host) {
				http.Error(writer, "Cross-site request rejected.", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(writer, request)
	})
}

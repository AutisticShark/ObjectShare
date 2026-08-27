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
	router.Use(securityHeaders)

	router.Get("/", handler.Index)
	router.Get("/assets/upload.js", handler.UploadScript)
	router.Get("/file/{id}", handler.FileView)
	router.Get("/health/live", handler.Live)
	router.Get("/health/ready", handler.Ready)

	router.Route("/api/v1", func(router chi.Router) {
		router.With(requireSameOrigin).Post("/upload", handler.Upload)
		router.With(requireSameOrigin).Post("/uploads/direct", handler.BeginDirectUpload)
		router.With(requireSameOrigin).Post("/uploads/direct/{id}/complete", handler.CompleteDirectUpload)
		router.With(requireSameOrigin).Post("/uploads/direct/{id}/abort", handler.AbortDirectUpload)
		router.Get("/download/{id}", handler.Download)
		router.With(requireSameOrigin).Post("/delete/{id}", handler.Delete)
		router.With(requireSameOrigin).Delete("/delete/{id}", handler.Delete)
		router.With(requireSameOrigin).Post("/update/{id}", handler.Update)
		router.With(requireSameOrigin).Put("/update/{id}", handler.Update)
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

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self' https://cdn.jsdelivr.net; connect-src 'self' https://*.r2.cloudflarestorage.com; style-src 'self' https://cdn.jsdelivr.net; font-src https://cdn.jsdelivr.net; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		writer.Header().Set("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(writer, request)
	})
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

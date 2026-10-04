package db

import (
	"context"
	"log/slog"
	"time"

	gormlogger "gorm.io/gorm/logger"
)

func init() {
	// Scan records its statement through GORM's package-level recorder, which
	// interpolates bound values whatever the configured logger says. Keep the
	// placeholders there too so no code path can log a value.
	gormlogger.RecorderParamsFilter = parameterizedOnly
}

func parameterizedOnly(_ context.Context, sql string, _ ...any) (string, []any) { return sql, nil }

// queryLogger routes GORM diagnostics through the application's structured
// logger. GORM's default logger writes colored lines to stdout with every
// bound value interpolated, which exposed password hashes and email addresses
// on failed or slow statements. Statements are logged with their $n
// placeholders only, and a missing row is an expected result, not an error.
func queryLogger() gormlogger.Interface {
	return gormlogger.NewSlogLogger(slog.Default(), gormlogger.Config{
		SlowThreshold:             200 * time.Millisecond,
		LogLevel:                  gormlogger.Warn,
		IgnoreRecordNotFoundError: true,
		ParameterizedQueries:      true,
	})
}

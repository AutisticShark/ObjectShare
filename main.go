package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/AutisticShark/ObjectShare/api"
	"github.com/AutisticShark/ObjectShare/api/htmx"
	appauth "github.com/AutisticShark/ObjectShare/auth"
	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/AutisticShark/ObjectShare/service"
	"github.com/google/uuid"
)

//go:embed template/*
var templateFiles embed.FS

func main() {
	if err := run(); err != nil {
		slog.Error("object-share stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "", "path to a JSON configuration file")
	healthcheck := flag.Bool("healthcheck", false, "check the local live endpoint and exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	createAdmin := flag.Bool("create-admin", false, "create the initial administrator and exit")
	adminEmail := flag.String("admin-email", "", "email address for -create-admin")
	adminName := flag.String("admin-name", "", "display name for -create-admin")
	adminPasswordFile := flag.String("admin-password-file", "", "file containing the password for -create-admin")
	adminPasswordStdin := flag.Bool("admin-password-stdin", false, "read the password from standard input for -create-admin")
	flag.Parse()
	if *showVersion {
		fmt.Println(config.GetVersion())
		return nil
	}
	if *healthcheck {
		return runHealthcheck()
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)
	cfg, err := config.LoadBootstrap(*configPath)
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}

	startupContext, cancelStartup := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelStartup()
	repository, err := db.Open(startupContext, cfg.Db)
	if err != nil {
		return err
	}
	defer repository.Close()
	if err := loadDatabaseConfiguration(startupContext, repository, cfg, logger); err != nil {
		return err
	}
	if *createAdmin {
		return createInitialAdmin(startupContext, repository, *adminEmail, *adminName, *adminPasswordFile, *adminPasswordStdin)
	}
	objectStore, err := service.New(cfg)
	if err != nil {
		return fmt.Errorf("initialize object storage: %w", err)
	}
	handler, err := htmx.New(cfg, repository, objectStore, templateFiles, logger)
	if err != nil {
		return fmt.Errorf("initialize HTTP handlers: %w", err)
	}

	server := &http.Server{
		Addr: cfg.Address, Handler: api.Router(handler, logger),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       cfg.ReadTimeout.Duration(), WriteTimeout: cfg.WriteTimeout.Duration(),
		IdleTimeout: cfg.IdleTimeout.Duration(), MaxHeaderBytes: 1 << 20,
		MaxHeaderValueCount: 100,
	}
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("server listening", "address", cfg.Address, "version", config.GetVersion())
		serverErrors <- server.ListenAndServe()
	}()

	signals, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve HTTP: %w", err)
	case <-signals.Done():
		logger.Info("shutdown requested")
		shutdownContext, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout.Duration())
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		return nil
	}
}

func loadDatabaseConfiguration(ctx context.Context, repository db.SettingsRepository, cfg *config.ServiceConfig, logger *slog.Logger) error {
	setting, err := repository.ApplicationSettings(ctx)
	if errors.Is(err, db.ErrNotFound) {
		if err := cfg.ValidateSeed(); err != nil {
			return fmt.Errorf("validate initial database configuration environment: %w", err)
		}
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("validate initial database configuration: %w", err)
		}
		seed, sealErr := config.SealRuntime(config.RuntimeFromService(cfg), cfg.SettingsKey)
		if sealErr != nil {
			return fmt.Errorf("protect initial database configuration: %w", sealErr)
		}
		if err := repository.InitializeApplicationSettings(ctx, seed); err != nil {
			return fmt.Errorf("initialize database configuration: %w", err)
		}
		setting, err = repository.ApplicationSettings(ctx)
	}
	if err != nil {
		return fmt.Errorf("load database configuration: %w", err)
	}
	runtime, err := config.OpenRuntime(setting.Value, cfg.SettingsKey)
	if err != nil {
		return fmt.Errorf("open database configuration: %w", err)
	}
	if err := config.ApplyRuntime(cfg, runtime); err != nil {
		return err
	}
	logger.Info("database configuration loaded", "updated_at", setting.UpdatedAt.UTC(), "updated_by", setting.UpdatedBy)
	return nil
}

func createInitialAdmin(ctx context.Context, repository db.AuthRepository, emailValue, nameValue, passwordFile string, passwordStdin bool) error {
	email, err := appauth.NormalizeEmail(emailValue)
	if err != nil {
		return fmt.Errorf("invalid administrator email: %w", err)
	}
	name, err := appauth.ValidateDisplayName(nameValue)
	if err != nil {
		return fmt.Errorf("invalid administrator display name: %w", err)
	}
	password := os.Getenv("OBJECTSHARE_ADMIN_PASSWORD")
	if passwordFile != "" && passwordStdin {
		return errors.New("provide only one of -admin-password-file or -admin-password-stdin")
	}
	if passwordFile != "" {
		data, err := os.ReadFile(passwordFile)
		if err != nil {
			return fmt.Errorf("read administrator password file: %w", err)
		}
		password = strings.TrimRight(string(data), "\r\n")
	} else if passwordStdin {
		data, err := io.ReadAll(io.LimitReader(os.Stdin, 513))
		if err != nil {
			return fmt.Errorf("read administrator password from standard input: %w", err)
		}
		password = strings.TrimRight(string(data), "\r\n")
	}
	if password == "" {
		return errors.New("provide -admin-password-file, -admin-password-stdin, or OBJECTSHARE_ADMIN_PASSWORD")
	}
	hash, err := appauth.HashPassword(password)
	if err != nil {
		return fmt.Errorf("invalid administrator password: %w", err)
	}
	user := &db.User{ID: uuid.NewString(), Email: email, DisplayName: name, PasswordHash: hash, Role: db.RoleAdmin, Active: true, TokenVersion: 1}
	if err := repository.BootstrapAdmin(ctx, user); err != nil {
		return fmt.Errorf("create initial administrator: %w", err)
	}
	fmt.Printf("Initial administrator created for %s.\n", email)
	return nil
}

func runHealthcheck() error {
	endpoint := os.Getenv("OBJECTSHARE_HEALTH_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080/health/live"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get(endpoint)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned %s", response.Status)
	}
	return nil
}

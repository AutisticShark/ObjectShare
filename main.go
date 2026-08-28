package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AutisticShark/ObjectShare/api"
	"github.com/AutisticShark/ObjectShare/api/htmx"
	"github.com/AutisticShark/ObjectShare/config"
	"github.com/AutisticShark/ObjectShare/db"
	"github.com/AutisticShark/ObjectShare/service"
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
	cfg, err := config.Load(*configPath)
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

package main

import (
	"ObjectShare/api/htmx"
	"ObjectShare/config"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/spf13/pflag"
	"net/http"
	"strconv"
	"time"
)

func main() {
	configFilePath := pflag.String("config", "", "config file path")
	pflag.Parse()

	if *configFilePath != "" {
		config.Viper.AddConfigPath(*configFilePath)
	}

	router := chi.NewRouter()

	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(middleware.Timeout(time.Duration(int64(config.Config.Timeout) * int64(time.Second))))

	router.Get("/", htmx.IndexV1)
	router.Get("/file/{id}", htmx.FileViewV1)

	router.Route("/api/v1", func(router chi.Router) {
		router.Post("/upload", htmx.UploadV1)
		router.Get("/download/{id}", htmx.DownloadV1)
		router.Delete("/delete/{id}", htmx.DeleteV1)
		router.Put("/update/{id}", htmx.UpdateV1)
	})

	port := strconv.Itoa(config.Config.Port)
	err := http.ListenAndServe(":"+port, router)
	if err != nil {
		panic(err)
	}
}

package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/AutisticShark/ObjectShare/config"
)

var ErrPresignUnsupported = errors.New("presigned downloads are not supported")

// MaxSinglePartUploadSize is R2's documented limit for a single PUT request.
// Larger objects require the S3 multipart API.
const MaxSinglePartUploadSize = int64(5 * 1024 * 1024 * 1024)

type ObjectInfo struct {
	Size        int64
	ContentType string
}

// DirectUploader is an optional object-store capability. Implementations return
// a short-lived URL so browsers can upload without proxying the file body
// through ObjectShare (or a CDN in front of it).
type DirectUploader interface {
	PresignPut(context.Context, string, int64, string) (string, error)
	Stat(context.Context, string) (*ObjectInfo, error)
}

type ObjectStore interface {
	Put(context.Context, string, io.Reader, int64, string) error
	Open(context.Context, string) (io.ReadCloser, error)
	Delete(context.Context, string) error
	PresignGet(context.Context, string, string) (string, error)
}

func New(cfg *config.ServiceConfig) (ObjectStore, error) {
	switch strings.ToLower(cfg.StorageService) {
	case "filesystem":
		return NewFileSystem(cfg.StoragePath)
	case "r2":
		return NewR2(cfg.R2)
	default:
		return nil, fmt.Errorf("unsupported storage service %q", cfg.StorageService)
	}
}

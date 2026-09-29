package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/AutisticShark/ObjectShare/config"
)

var ErrPresignUnsupported = errors.New("presigned downloads are not supported")

// MaxSinglePartUploadSize is the common maximum used for a single PUT across
// the supported S3-compatible services. Larger objects require multipart
// upload support.
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
	// Copy duplicates an object server-side, preserving its content type. The
	// finalize step uses it to publish a staged upload under its final key.
	Copy(ctx context.Context, sourceKey, destinationKey string) error
	DirectUploadPolicy() DirectUploadPolicy
}

// PendingUploadKey is the staging key a presigned direct upload writes to. A
// presigned PUT stays valid until it expires, so it must never target the key a
// finished file is served from: the finalize step verifies the staged object,
// copies it to the file's real key, and deletes the staged copy.
func PendingUploadKey(fileID string) string { return "pending/" + fileID }

type DirectUploadPolicy struct {
	Expires        time.Duration
	MaxSize        int64
	ConnectSources []string
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
	case "s3":
		return NewS3(cfg.S3)
	case "b2":
		return NewB2(cfg.B2)
	case "oss":
		return NewOSS(cfg.OSS)
	case "cos":
		return NewCOS(cfg.COS)
	case "oci":
		return NewOCI(cfg.OCI)
	case "gcs":
		return NewGCS(cfg.GCS)
	default:
		return nil, fmt.Errorf("unsupported storage service %q", cfg.StorageService)
	}
}

# ObjectShare

ObjectShare is a small self-hosted file sharing service written in Go. Files are shared through unlisted UUID links; the uploading browser receives an HTTP-only owner token that permits rename and deletion.

## Preview

![ObjectShare v0.1.0](./.github/ObjectShare_0.1.0.png)

## Features

- Streaming, size-limited uploads with SHA-256 and SHA3-256 checksums
- Tabler UI with HTMX progressive enhancement and native-form fallbacks
- Filesystem or Cloudflare R2 object storage
- Direct-to-R2 uploads that avoid reverse-proxy request-body limits
- PostgreSQL metadata with bounded connection pools
- Optional AES-256-GCM server-side encryption at rest
- Owner-only rename and permanent deletion
- Graceful shutdown, health endpoints, secure response headers, and structured logs
- Multi-stage, non-root, read-only container image
- Docker Compose development/single-node deployment
- CI, vulnerability scanning, SBOM/provenance, and multi-architecture publishing to Docker Hub and GHCR

ObjectShare does not provide user accounts or access-controlled downloads. Anyone with a file URL can download it. Put it behind an authentication-aware reverse proxy if private sharing is required.

## Roadmap

- [x] File upload
- [x] File download
- [ ] Better upload UI
- [ ] File sharing & permission
- [x] File deletion
- [ ] User management
- [ ] User authentication
- [ ] User authorization
- [x] Server-side encryption & decryption
- [ ] Client-side encryption & decryption

HTMX is intentionally part of the frontend architecture. The native forms are accessibility and no-JavaScript fallbacks; planned login, account, permission, and user-management interactions will use HTMX progressive enhancement.

### Supported Object Storage Services

- [x] Cloudflare R2
- [ ] AWS S3
- [ ] Backblaze B2
- [ ] Alibaba Cloud OSS
- [ ] Tencent Cloud COS
- [ ] Google Cloud Storage
- [ ] Oracle Cloud Object Storage
- [ ] Microsoft Azure Blob Storage

## Quick start with Docker Compose

```sh
cp .env.example .env
# Edit .env and replace POSTGRES_PASSWORD.
docker compose up --build -d
```

Open <http://localhost:8080>. Compose uses PostgreSQL 18 and a persistent local object volume. Stop it with `docker compose down`; add `--volumes` only when you intentionally want to delete all stored data.

For HTTPS deployments, terminate TLS at a reverse proxy and set `OBJECTSHARE_SECURE_COOKIES=true`. Back up both named volumes together so metadata and objects remain consistent.

## Run from source

Requirements: Go 1.27 and PostgreSQL 18 (PostgreSQL 17 is also supported).

```sh
cp config.json.example config.json
# Edit database credentials and storage settings.
go run . -config config.json
```

Configuration is read from the optional JSON file and then overridden by `OBJECTSHARE_*` environment variables. A config file is not required when all settings are supplied through the environment. The most useful variables are:

| Variable | Default | Purpose |
| --- | --- | --- |
| `OBJECTSHARE_ADDRESS` | `:8080` | HTTP listen address |
| `OBJECTSHARE_MAX_FILE_SIZE_MB` | `100` | Per-file upload limit |
| `OBJECTSHARE_STORAGE_SERVICE` | `filesystem` | `filesystem` or `r2` |
| `OBJECTSHARE_STORAGE_PATH` | `data/objects` | Filesystem object directory |
| `OBJECTSHARE_DB_*` | varies | PostgreSQL connection and pool settings |
| `OBJECTSHARE_SECURE_COOKIES` | `false` | Require HTTPS for owner cookies |
| `OBJECTSHARE_ENCRYPTION_ENABLED` | `false` | Enable encryption at rest |
| `OBJECTSHARE_ENCRYPTION_KEY` | empty | Base64/hex encoded 32-byte key |

Generate an encryption key with `openssl rand -base64 32`. Losing or changing this key makes existing encrypted files unrecoverable. Encrypted objects are authenticated before download and are held in memory during encryption/decryption. To bound memory use, encrypted mode limits files to 128 MiB and permits one cryptographic operation per application replica at a time.

### Cloudflare R2

Set `OBJECTSHARE_STORAGE_SERVICE=r2` and provide:

- `OBJECTSHARE_R2_BUCKET_NAME`
- `OBJECTSHARE_R2_ACCOUNT_ID`
- `OBJECTSHARE_R2_ACCESS_KEY_ID`
- `OBJECTSHARE_R2_SECRET_ACCESS_KEY`
- `OBJECTSHARE_R2_PRESIGN_TIMEOUT` (default `10m`, maximum `168h`)
- `OBJECTSHARE_R2_UPLOAD_PRESIGN_TIMEOUT` (default `1h`, maximum `168h`)

The R2 token only needs object read/write permissions for the configured bucket. Downloads use short-lived presigned URLs unless server-side encryption is enabled.

When R2 is selected and server-side encryption is disabled, JavaScript-enabled browsers upload directly to a short-lived, content-type-bound R2 PUT URL. Only the authorization and completion requests pass through ObjectShare, so a Cloudflare-proxied deployment is not constrained by Cloudflare's 100 MB Free/Pro, 200 MB Business, or default 500 MB Enterprise request-body limits. ObjectShare verifies the uploaded object's key, size, content type, expiry, and one-time owner token before publishing its share page. Single-part direct uploads are limited to R2's 5 GiB PUT limit; larger R2 objects require multipart upload support.

These limits and the direct-upload pattern are documented in Cloudflare's [413 limit reference](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/4xx-client-error/error-413/), [R2 limits](https://developers.cloudflare.com/r2/platform/limits/), and [upload guidance](https://developers.cloudflare.com/r2/objects/upload-objects/).

Direct browser uploads require an R2 CORS policy. Replace the origin below with the exact public origin serving ObjectShare (and add a localhost origin separately for local development):

```json
[
  {
    "AllowedOrigins": ["https://share.example.com"],
    "AllowedMethods": ["PUT"],
    "AllowedHeaders": ["Content-Type"],
    "MaxAgeSeconds": 3600
  }
]
```

The direct path does not claim server-verified SHA checksums because the application never receives the file bytes. The details page labels those checksums as unavailable. Enable server-side encryption, or use filesystem storage, when application-side hashing is required; those modes stream the upload through ObjectShare and therefore remain subject to the front proxy's body-size limit.

Server-side encryption and direct-to-R2 upload are intentionally mutually exclusive: encryption keys remain on the server, so encrypted file bodies must pass through ObjectShare.

## Production checklist

- Put the service behind HTTPS and enable secure cookies.
- Use a long, unique PostgreSQL password and TLS (`ssl_mode=require` or stronger) for external databases.
- Keep the database private; only publish the application port.
- Use R2 for horizontally scaled deployments. Filesystem storage is intended for a single application replica.
- Persist and back up object storage and PostgreSQL consistently.
- Set upload limits and proxy timeouts deliberately; apply rate limiting at the ingress/reverse proxy.
- Keep the encryption key in a secret manager, never in `config.json` or the image.
- Monitor `/health/live` for process health and `/health/ready` for database readiness.
- Test upgrades and restores in a staging environment before production rollout.

## Container publishing

`.github/workflows/container-publish.yml` publishes `linux/amd64` and `linux/arm64` images on a GitHub Release and can also be run manually. Configure these repository settings:

- Variable `DOCKERHUB_USERNAME`: Docker Hub account or organization
- Variable `DOCKERHUB_IMAGE`: full image name, for example `acme/objectshare`
- Secret `DOCKERHUB_TOKEN`: a Docker Hub access token with push access

GHCR uses the workflow-scoped `GITHUB_TOKEN`; no additional secret is needed. Published images include BuildKit provenance and an SBOM. Package visibility is managed from the repository's Packages settings.

## Development

```sh
go mod verify
go test -race ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
```

CI also verifies formatting and builds the container. Dependency and action updates are proposed weekly by Dependabot.

## License

[GPL-3.0-only](./LICENSE)

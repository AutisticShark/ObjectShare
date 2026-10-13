# syntax=docker/dockerfile:1.28
ARG GO_VERSION=1.27.2
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
RUN apk add --no-cache ca-certificates tzdata && mkdir -p /out/data/objects /out/data/tmp
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X github.com/AutisticShark/ObjectShare/config.Version=${VERSION}" \
    -o /out/object-share ./

FROM scratch
ARG VERSION=dev
LABEL org.opencontainers.image.title="ObjectShare" \
      org.opencontainers.image.description="A small self-hosted file sharing service" \
      org.opencontainers.image.source="https://github.com/AutisticShark/ObjectShare" \
      org.opencontainers.image.licenses="GPL-3.0-only" \
      org.opencontainers.image.version=$VERSION
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=build /out/object-share /object-share
COPY --from=build --chown=65532:65532 /out/data /var/lib/objectshare
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["/object-share", "-healthcheck"]
# The image runs as a non-root user and the process default (data/objects) is
# relative to an unwritable working directory, so default to the volume path.
# This is only a default: storage_path in a mounted config.json or an explicit
# OBJECTSHARE_STORAGE_PATH still takes precedence at the first import.
ENV OBJECTSHARE_DEFAULT_STORAGE_PATH=/var/lib/objectshare/objects
# Proxied multipart uploads above 32 MiB are spooled to TMPDIR while they are
# received. Keep that on the data volume, sized for uploads, rather than in a
# small in-memory /tmp.
ENV TMPDIR=/var/lib/objectshare/tmp
ENTRYPOINT ["/object-share"]

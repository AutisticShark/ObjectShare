# syntax=docker/dockerfile:1.18
ARG GO_VERSION=1.27.0
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine3.24@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
RUN apk add --no-cache ca-certificates tzdata && mkdir -p /out/data/objects
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
ENTRYPOINT ["/object-share"]

# syntax=docker/dockerfile:1

# Build stage: pinned by digest (golang:1.27.2-alpine, multi-arch index).
FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS builder

WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath GOTOOLCHAIN=local

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY cmd ./cmd
COPY internal ./internal

ARG TARGETOS TARGETARCH
RUN GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w -buildid=" -o /out/nostr-oauth2-server ./cmd/nostr-oauth2-server

# Runtime stage: distroless static (CA certificates, tzdata, no shell),
# non-root user 65532, pinned by digest (static-debian13:nonroot index).
FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3

COPY --from=builder /out/nostr-oauth2-server /nostr-oauth2-server

USER 65532:65532
EXPOSE 8080

# No configuration is baked in. Mount a config file and pass
# -config /etc/nostr-auth/config.yaml, or use environment variables
# (see README). The process needs no writable filesystem.
ENTRYPOINT ["/nostr-oauth2-server"]
CMD ["-config", "/etc/nostr-auth/config.yaml"]

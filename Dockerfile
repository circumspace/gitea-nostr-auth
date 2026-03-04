# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install git for go modules
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o nostr-oauth2-server ./cmd/nostr-oauth2-server

# Runtime stage
FROM alpine:3.19

RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/nostr-oauth2-server .

# Copy default config
COPY config.example.yaml /app/config.yaml

# Expose port
EXPOSE 8080

# Run the server
ENTRYPOINT ["./nostr-oauth2-server"]
CMD ["-config", "/app/config.yaml"]

# Multi-stage Dockerfile for GoUpload
# Builds a static Linux binary in a Go builder image and copies it into a small runtime image.

# Build stage
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /goupload .

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata curl

# Create non-root user
RUN addgroup -S goupload && adduser -S goupload -G goupload

# Create necessary directories
RUN mkdir -p /app/templates /app/data /app/output

# Copy binary from builder
COPY --from=builder /goupload /usr/local/bin/goupload

# Copy templates
COPY --from=builder /src/templates /app/templates

# Set working directory
WORKDIR /app

# Set permissions
RUN chown -R goupload:goupload /app

# Switch to non-root user
USER goupload

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD goupload --version || exit 1

# Use the binary as the container entrypoint
ENTRYPOINT ["/usr/local/bin/goupload"]

# Default command (show help)
CMD ["--help"]

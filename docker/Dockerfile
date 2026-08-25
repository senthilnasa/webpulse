# Stage 1: Build Go Server & CLI
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy dependency files
COPY go.mod ./
COPY go.sum* ./
RUN go mod download

# Copy source code
COPY . .

# Build WebPulse Server binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/bin/webpulse-server ./cmd/server

# Build WebPulse CLI binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/bin/webpulse ./cmd/webpulse

# Stage 2: Final Minimal Runtime Image
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binaries and static frontend
COPY --from=builder /app/bin/webpulse-server /app/webpulse-server
COPY --from=builder /app/bin/webpulse /usr/local/bin/webpulse
COPY --from=builder /app/frontend/dist /app/frontend/dist

# Expose HTTP port
EXPOSE 8080

# Environment variables
ENV PORT=8080
ENV DB_PATH=/app/data/webpulse.json

# Default entrypoint
CMD ["/app/webpulse-server", "--port", "8080", "--db", "/app/data/webpulse.json"]

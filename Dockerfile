# ---------- build stage ----------
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o /app/sso-server ./cmd/server

# ---------- runtime stage ----------
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/sso-server .

RUN mkdir -p /app/data

EXPOSE 8080

ENTRYPOINT ["/app/sso-server"]

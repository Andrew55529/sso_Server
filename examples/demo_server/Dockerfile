FROM golang:1.24-alpine AS builder
WORKDIR /src
# Copy only what's needed to build the example server
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /demo_server ./examples/demo_server

FROM alpine:3.21
RUN apk --no-cache add ca-certificates
COPY --from=builder /demo_server /demo_server
EXPOSE 8081
ENTRYPOINT ["/demo_server"]

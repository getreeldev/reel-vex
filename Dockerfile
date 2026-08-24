FROM golang:1.27-alpine AS build
WORKDIR /src
ARG VERSION=dev
COPY go.mod go.sum ./
# Retry: proxy.golang.org occasionally returns a transient HTTP/2 stream error
# mid-download (hit on the v0.10.0 release build); a couple of retries clears it.
RUN for i in 1 2 3; do go mod download && break || { echo "go mod download attempt $i failed; retrying"; sleep 3; }; done
COPY . .
RUN go build -ldflags="-X main.version=${VERSION}" -o /reel-vex ./cmd/server

FROM alpine:3.21
# Upgrade first so libcrypto3/libssl3/musl/etc. pick up any in-series CVE
# patches that landed after the base image tag was cut.
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates
COPY --from=build /reel-vex /usr/local/bin/reel-vex
# Drop root: the server only reads a (read-only) config mount and talks to
# Postgres over the network — it never writes to the container filesystem, and
# :8080 is unprivileged. nobody (65534) ships with the alpine base image.
USER nobody
ENTRYPOINT ["reel-vex"]

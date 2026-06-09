FROM golang:1.26-alpine AS build
WORKDIR /src
ARG VERSION=dev
COPY go.mod go.sum ./
RUN go mod download
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

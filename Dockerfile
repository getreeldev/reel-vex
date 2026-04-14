FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /reel-vex ./cmd/server

FROM alpine:3.21
# Upgrade first so libcrypto3/libssl3/musl/etc. pick up any in-series CVE
# patches that landed after the base image tag was cut.
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates
COPY --from=build /reel-vex /usr/local/bin/reel-vex
ENTRYPOINT ["reel-vex"]

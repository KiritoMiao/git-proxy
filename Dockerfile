# syntax=docker/dockerfile:1

FROM node:24-alpine AS assets
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci
COPY internal/web/templates ./internal/web/templates
COPY internal/web/static ./internal/web/static
RUN npm run build

FROM golang:1.26-alpine AS build
ARG REVISION=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY --from=assets /src/internal/web/static/app.css ./internal/web/static/app.css
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/kirito/git-proxy/internal/version.Revision=${REVISION}" -o /out/git-proxy ./cmd/git-proxy

FROM alpine:3.23
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/KiritoMiao/git-proxy" \
    org.opencontainers.image.licenses="GPL-3.0-only" \
    org.opencontainers.image.version="${VERSION}" \
    org.opencontainers.image.revision="${REVISION}"
RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 10001 gitproxy \
    && adduser -S -D -H -u 10001 -G gitproxy gitproxy \
    && mkdir /data \
    && chown gitproxy:gitproxy /data \
    && chmod 0700 /data
COPY --from=build /out/git-proxy /usr/local/bin/git-proxy
COPY LICENSE /usr/share/licenses/git-proxy/LICENSE
USER 10001:10001
EXPOSE 2222 8080
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/git-proxy"]
CMD ["-data", "/data", "-ssh", "0.0.0.0:2222", "-http", "0.0.0.0:8080"]

# the admin web does not depend on the platform: it is built once
FROM --platform=$BUILDPLATFORM node:24-alpine AS web
WORKDIR /src/web/admin
COPY web/admin/package.json web/admin/package-lock.json ./
RUN npm ci
COPY web/admin/ ./
RUN npm run build

# pure Go (no CGO): it cross-compiles for the target platform without emulation
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH
ENV CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/internal/admin/ui/dist ./internal/admin/ui/dist
RUN go build -trimpath -ldflags '-s -w' -o /app ./cmd/minioidc

FROM scratch AS final
EXPOSE 8000
# the optional LDAP server (ldap_server.address)
EXPOSE 3389
COPY --from=build /app /app
COPY --from=build /src/templates /templates
COPY --from=build /src/static /static

ENTRYPOINT ["/app"]

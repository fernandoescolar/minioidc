FROM golang:1.22-alpine AS build
ENV GOOS=linux
RUN apk add --no-cache \
    gcc \
    musl-dev
WORKDIR /src
COPY . .
RUN go mod download \
 && go build -o /app -a -ldflags '-linkmode external -extldflags "-static"' ./cmd/minioidc/main.go

FROM scratch AS final
EXPOSE 8000
COPY --from=build /app /app
COPY --from=build /src/templates /templates
COPY --from=build /src/static /static

ENTRYPOINT ["/app"]

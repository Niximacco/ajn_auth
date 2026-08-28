FROM golang:1.25-alpine AS build

WORKDIR /src

# The module files come first so the dependency download is cached separately
# from the source: editing a handler should not re-download the sdk.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY pkg/ ./pkg/

# CGO off gives a static binary, which is what lets the runtime stage be a bare
# alpine with nothing in it but certificates.
#
# The pages, the stylesheet and both email bodies are compiled into that binary
# by the go:embed directives in internal/web and the templates in
# internal/email, so there is nothing to copy into the runtime stage and nothing
# to fetch at start.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /bin/ajn-auth ./cmd/ajn-auth

FROM alpine:3.21 AS deploy
RUN apk --no-cache add ca-certificates && update-ca-certificates

# Nothing here needs to be root, and Cloud Run does not require it.
RUN adduser -D -u 10001 ajnauth
USER ajnauth

COPY --from=build /bin/ajn-auth /bin/ajn-auth
ENTRYPOINT ["/bin/ajn-auth"]
EXPOSE 8080

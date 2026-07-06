# syntax=docker/dockerfile:1

# ---- base: source + deps ----
FROM golang:1.23-alpine AS base
WORKDIR /src

# Module files first for layer caching. (No deps: stdlib only.)
COPY go.mod ./
RUN go mod download

COPY . .

# ---- test: vet, build, test (run inside the image) ----
FROM base AS test
RUN go vet ./...
RUN go build ./...
RUN go test ./...

# ---- build the binary (chained off test: tests must pass first) ----
FROM test AS build
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/auth-gateway .

# ---- runtime ----
FROM gcr.io/distroless/static-debian12:nonroot AS runtime
COPY --from=build /out/auth-gateway /auth-gateway
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/auth-gateway"]

# syntax=docker/dockerfile:1

# ---- base: source + deps ----
# Pinned to the build platform (the runner's native arch) so vet/test/compile
# all run natively — no QEMU emulation, even for cross-arch targets.
FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS base
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
# TARGETARCH is supplied by buildx per requested platform; Go cross-compiles
# the binary natively for it (arm64/amd64/…) without emulation.
FROM test AS build
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/auth-gateway .

# ---- runtime ----
FROM gcr.io/distroless/static-debian12:nonroot AS runtime
COPY --from=build /out/auth-gateway /auth-gateway
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/auth-gateway"]

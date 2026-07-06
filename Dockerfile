# syntax=docker/dockerfile:1

# ---- build ----
FROM golang:1.23-alpine AS build
WORKDIR /src

# Module files first for layer caching. (No deps: stdlib only.)
COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/auth-gateway .

# ---- runtime ----
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/auth-gateway /auth-gateway
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/auth-gateway"]

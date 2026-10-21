FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
COPY VERSION ./VERSION
RUN VERSION=$(cat VERSION) && GOMAXPROCS=1 GOMEMLIMIT=320MiB CGO_ENABLED=0 go build -p=1 -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/xraywatch-node-agent ./cmd/xraywatch-node-agent
RUN mkdir -p /out/state && touch /out/state/.keep

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/xraywatch-node-agent /xraywatch-node-agent
COPY --from=build --chown=65532:65532 /out/state /var/lib/xraywatch
USER 65532:65532
ENTRYPOINT ["/xraywatch-node-agent"]


# Risk Guard image. Build from the repo root:
#   docker build -f deployments/docker/Dockerfile -t riskguard:local .
# Same flags as the release binary, so the image binary hashes like a host build of the same arch.
# Plain Dockerfile syntax (no BuildKit-only features) so hosts without buildx can build it.
FROM golang:1.26.10-alpine@sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /out/riskguard ./cmd/riskguard

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/riskguard /usr/local/bin/riskguard
ENTRYPOINT ["/usr/local/bin/riskguard"]
CMD ["-config", "/etc/riskguard/config.yaml"]

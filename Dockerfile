FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X github.com/Alex9001/whodis/v2.version=${VERSION}" \
    -o /out/whodis ./cmd/whodis
RUN ./scripts/collect-go-licenses.sh /out/licenses/third-party && cp LICENSE /out/licenses/LICENSE

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/whodis /usr/local/bin/whodis
COPY --from=build /out/licenses /usr/share/licenses/whodis
ENTRYPOINT ["/usr/local/bin/whodis"]
CMD ["--help"]

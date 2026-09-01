FROM golang:1.27-alpine AS build

WORKDIR /src
COPY v2/go.mod v2/go.sum ./v2/
RUN go -C v2 mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go -C v2 build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X github.com/Alex9001/whodis/v2.version=${VERSION}" \
    -o /out/whodis ./cmd/whodis
RUN ./scripts/collect-go-licenses.sh /out/licenses/third-party && cp LICENSE /out/licenses/LICENSE

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/whodis /usr/local/bin/whodis
COPY --from=build /out/licenses /usr/share/licenses/whodis
ENTRYPOINT ["/usr/local/bin/whodis"]
CMD ["--help"]

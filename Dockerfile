# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH VERSION=1.0.0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ui.html ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/fastdav .

FROM scratch
COPY --from=build /out/fastdav /usr/local/bin/fastdav
ENV PATH=/usr/local/bin \
    LISTEN=:8080 DATA_DIR=/data CONFIG_DIR=/config \
    PUID=99 PGID=100 UMASK=000
EXPOSE 8080
VOLUME ["/config"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD ["fastdav", "healthcheck"]
ENTRYPOINT ["fastdav"]
CMD ["serve"]

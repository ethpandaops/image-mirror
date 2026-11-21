FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /image-mirror .

FROM alpine:3.22
ARG TARGETARCH
ARG REGCTL_VERSION=v0.11.7
RUN apk add --no-cache bash ca-certificates curl jq github-cli \
 && case "$TARGETARCH" in \
      amd64) sum=3737fbbdd791e04e7a831640b681f3397a376498e80e2ad9b1b2d27296f239bc ;; \
      arm64) sum=9f349bab5c407ac04f3dabf99c7c7a6b0f9e9723c23f2775380e804d02c6dbb9 ;; \
    esac \
 && curl -fsSL -o /usr/local/bin/regctl "https://github.com/regclient/regclient/releases/download/${REGCTL_VERSION}/regctl-linux-${TARGETARCH}" \
 && echo "${sum}  /usr/local/bin/regctl" | sha256sum -c - \
 && chmod +x /usr/local/bin/regctl \
 && adduser -D -u 10001 mirror
COPY --from=build /image-mirror /usr/local/bin/image-mirror
COPY scripts/mirror.sh /app/mirror.sh
USER mirror
WORKDIR /home/mirror
ENTRYPOINT ["image-mirror", "-script", "/app/mirror.sh"]

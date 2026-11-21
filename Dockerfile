# Base images are pinned by digest and tools by version and checksum, so a
# rebuild of the same commit gets the same verifier. Bump them deliberately.
FROM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /image-mirror .

FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f AS tools
ARG TARGETARCH
ARG REGCTL_VERSION=v0.11.7
ARG GH_VERSION=2.105.0
ARG JQ_VERSION=1.8.2
RUN apk add --no-cache curl \
 && case "$TARGETARCH" in \
      amd64) regctl=3737fbbdd791e04e7a831640b681f3397a376498e80e2ad9b1b2d27296f239bc \
             gh=79e7ab5db738c48777b696e374f8b428f0647debfb424f44d2f426370407fe2f \
             jq=b1c22172dd303f3be49e935aa56aa48a8b7a46e0bc838b4997d3bb451495870f ;; \
      arm64) regctl=9f349bab5c407ac04f3dabf99c7c7a6b0f9e9723c23f2775380e804d02c6dbb9 \
             gh=b1278c75107423d818f1937fd92cafc9e5e9b606631568f68d7fb816f5885a02 \
             jq=8b85c817833814ddca00a144c33705546355afccf0cf39b188f3cdb48b852309 ;; \
      *) echo "unsupported arch $TARGETARCH"; exit 1 ;; \
    esac \
 && mkdir /out \
 && curl -fsSL -o /out/regctl "https://github.com/regclient/regclient/releases/download/${REGCTL_VERSION}/regctl-linux-${TARGETARCH}" \
 && curl -fsSL -o /tmp/gh.tgz "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${TARGETARCH}.tar.gz" \
 && curl -fsSL -o /out/jq "https://github.com/jqlang/jq/releases/download/jq-${JQ_VERSION}/jq-linux-${TARGETARCH}" \
 && printf '%s  %s\n' "$regctl" /out/regctl "$gh" /tmp/gh.tgz "$jq" /out/jq | sha256sum -c - \
 && tar -xzf /tmp/gh.tgz -C /tmp \
 && mv "/tmp/gh_${GH_VERSION}_linux_${TARGETARCH}/bin/gh" /out/gh \
 && chmod 0755 /out/*

FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
# bash is the only package added; CA roots come with the base image.
RUN apk add --no-cache bash \
 && addgroup -g 10001 mirror \
 && adduser -D -u 10001 -G mirror mirror
COPY --from=tools /out/ /usr/local/bin/
COPY --from=build /image-mirror /usr/local/bin/image-mirror
COPY scripts/mirror.sh /app/mirror.sh
# Numeric, so runAsNonRoot can check it.
USER 10001:10001
WORKDIR /home/mirror
ENTRYPOINT ["image-mirror", "-script", "/app/mirror.sh"]

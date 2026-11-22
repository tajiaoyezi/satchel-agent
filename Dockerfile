# syntax=docker/dockerfile:1
# 节点守护镜像（m2-09 node-lifecycle）：Go 构建阶段 + 以 nginx 官方镜像为底的运行阶段。
# 构建需通过 --build-context satchel=../satchel 提供主控共用 pkg/ 契约包（go.mod replace ../satchel）。

FROM golang:1.26-bookworm AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=0.0.0-dev
ARG COMMIT=unknown
ARG DATE=unknown

WORKDIR /workspace
COPY --from=satchel go.mod go.sum ./satchel/
COPY --from=satchel pkg ./satchel/pkg/

WORKDIR /workspace/satchel-agent
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build \
    -trimpath \
    -tags with_quic,with_utls,with_wireguard,with_gvisor \
    -ldflags="-s -w -X github.com/satchel/satchel-agent/internal/buildinfo.Version=${VERSION} -X github.com/satchel/satchel-agent/internal/buildinfo.Commit=${COMMIT} -X github.com/satchel/satchel-agent/internal/buildinfo.Date=${DATE}" \
    -o /out/satchel-agent ./cmd/satchel-agent

# 运行阶段：预装 nginx 供后续网站与反代能力使用；设 ENV DOCKER=1 禁止容器内原地自更新/卸载。
FROM nginx:mainline-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        tzdata \
        curl \
        procps \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/nginx/cert /etc/nginx/servers /etc/nginx/stream_servers /etc/nginx/html /etc/satchel-agent /var/lib/satchel-agent \
    && chmod 0700 /etc/satchel-agent \
    && chmod 0755 /var/lib/satchel-agent

COPY --from=builder /out/satchel-agent /usr/local/bin/satchel-agent
COPY docker-entrypoint.sh /usr/local/bin/satchel-agent-entrypoint
RUN chmod 0755 /usr/local/bin/satchel-agent /usr/local/bin/satchel-agent-entrypoint

ENV DOCKER=1
VOLUME ["/etc/satchel-agent", "/var/lib/satchel-agent"]

# nginx 基础镜像默认 STOPSIGNAL 为 SIGQUIT，Go 进程收到 SIGQUIT 会打栈并退出 2；改为 SIGTERM 以匹配优雅停止。
STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/satchel-agent-entrypoint"]
CMD ["run"]

# syntax=docker/dockerfile:1

# frps: the official release tarball, checked against the SHA-256 published for it
FROM alpine:3.23 AS frp
ARG TARGETARCH
ARG FRP_VERSION=0.71.1
RUN <<-EOF
	set -eu
	case "$TARGETARCH" in
	amd64) sha256=1d9875210972a5d1a62b2dc4c48df45ab0af05d3ca1b5e494a014428259df803 ;;
	arm64) sha256=8edf590b0c396fa42f9c147121a76af83cfc2002b08f5aef0ea1008c43482019 ;;
	*) echo "no pinned frp for $TARGETARCH" >&2; exit 1 ;;
	esac
	dir="frp_${FRP_VERSION}_linux_${TARGETARCH}"
	wget -O frp.tar.gz "https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/${dir}.tar.gz"
	echo "$sha256  frp.tar.gz" | sha256sum -c -
	tar -xzf frp.tar.gz -C /usr/local/bin --strip-components=1 "$dir/frps"
EOF

FROM alpine:3.23 AS frps
COPY --from=frp /usr/local/bin/frps /usr/local/bin/frps
ENTRYPOINT ["frps"]
CMD ["-c", "/etc/frps/frps.toml"]

# plugin: standard library only; the registries come in as a mount
FROM python:3.13-slim AS plugin
WORKDIR /app
COPY ctl ctl
USER nobody
CMD ["python", "-m", "ctl.plugin", "/state"]

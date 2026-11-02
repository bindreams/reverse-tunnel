# syntax=docker/dockerfile:1

# frps, pinned by SHA-256 per architecture
FROM alpine:3.23 AS frp
ARG TARGETARCH
RUN <<-EOF
	set -eu
	case "$TARGETARCH" in
	amd64) sha256=1d9875210972a5d1a62b2dc4c48df45ab0af05d3ca1b5e494a014428259df803 ;;
	arm64) sha256=8edf590b0c396fa42f9c147121a76af83cfc2002b08f5aef0ea1008c43482019 ;;
	*) echo "no pinned frp for $TARGETARCH" >&2; exit 1 ;;
	esac
	dir="frp_0.71.1_linux_${TARGETARCH}"
	wget -O frp.tar.gz "https://github.com/fatedier/frp/releases/download/v0.71.1/${dir}.tar.gz"
	echo "$sha256  frp.tar.gz" | sha256sum -c -
	tar -xzf frp.tar.gz -C /usr/local/bin --strip-components=1 "$dir/frps"
EOF

FROM alpine:3.23 AS frps
COPY --from=frp /usr/local/bin/frps /usr/local/bin/frps
ENTRYPOINT ["frps"]
CMD ["-c", "/etc/frps/frps.toml"]

# plugin: ruamel.yaml, the release uv.lock pins (a test checks); the registries are mounted
FROM python:3.13-slim AS plugin
WORKDIR /app
RUN pip install --no-cache-dir --require-hashes -r /dev/stdin <<-EOF
	ruamel.yaml==0.19.1 --hash=sha256:27592957fedf6e0b62f281e96effd28043345e0e66001f97683aa9a40c667c93
EOF
COPY ctl ctl
USER nobody
CMD ["python", "-m", "ctl.plugin", "/state"]

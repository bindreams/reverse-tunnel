# syntax=docker/dockerfile:1

# The base image is pinned by digest, and so is frps: the ARG defaults below equal the frps entries of
# binaries.lock.toml (`linux-x86_64` and `linux-aarch64`), and tests/unit/test_bridge_files.py fails if they drift.
# They are defaults so that a plain `docker compose build` works; a build argument overrides them deliberately.

# frps =================================================================================================================
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS frps

ARG TARGETARCH
ARG FRP_AMD64_URL=https://github.com/fatedier/frp/releases/download/v0.71.0/frp_0.71.0_linux_amd64.tar.gz
ARG FRP_AMD64_SHA256=84f27e39f11169f7adcef8e8b70c9329de17747b1f14dad9fb95eef5682ea716
ARG FRP_AMD64_MEMBER=frp_0.71.0_linux_amd64/frps
ARG FRP_AMD64_MEMBER_SHA256=b95dee2bf29a021c562565cdf2116376b9fa7590361bd36ef57041a04d0e6654
ARG FRP_ARM64_URL=https://github.com/fatedier/frp/releases/download/v0.71.0/frp_0.71.0_linux_arm64.tar.gz
ARG FRP_ARM64_SHA256=f33c293c275d8fc68c654b6fba8f10b2551d6463d09a9fc9cffb7227eae82266
ARG FRP_ARM64_MEMBER=frp_0.71.0_linux_arm64/frps
ARG FRP_ARM64_MEMBER_SHA256=68263b9cab7d9a570593fd8e0593c5a4bafdd35f0dc386e9814ade063ffa6120

# The archive is checked before it is read, and the one member that is extracted is checked again.
RUN <<-'EOF'
	set -eu
	case "$TARGETARCH" in
	amd64)
		url=$FRP_AMD64_URL archive_sha256=$FRP_AMD64_SHA256 member=$FRP_AMD64_MEMBER member_sha256=$FRP_AMD64_MEMBER_SHA256
		;;
	arm64)
		url=$FRP_ARM64_URL archive_sha256=$FRP_ARM64_SHA256 member=$FRP_ARM64_MEMBER member_sha256=$FRP_ARM64_MEMBER_SHA256
		;;
	*)
		echo "no frps is pinned for the architecture '$TARGETARCH'" >&2
		exit 1
		;;
	esac
	wget -qO /tmp/frp.tar.gz "$url"
	echo "$archive_sha256  /tmp/frp.tar.gz" | sha256sum -c -
	tar -xzOf /tmp/frp.tar.gz "$member" > /frps
	echo "$member_sha256  /frps" | sha256sum -c -
	chmod 0755 /frps
EOF

# Image ================================================================================================================
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

COPY --from=frps /frps /usr/local/bin/frps
COPY --chmod=0755 entrypoint.sh /usr/local/bin/bridge-entrypoint

# compose.yaml mounts secrets/token and bridge/frps.toml under /rt, so frps.toml's relative paths resolve there.
WORKDIR /rt
EXPOSE 8001/tcp 8001/udp 8080/tcp 7500/tcp

ENTRYPOINT ["/usr/local/bin/bridge-entrypoint"]
CMD ["frps", "-c", "bridge/frps.toml"]

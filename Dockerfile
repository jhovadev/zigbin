FROM debian:stable-slim AS builder

ARG MINISIG=0.12
ARG ZIG_MINISIG=RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U
ARG TARGETPLATFORM

RUN apt-get update -yq && \
    apt-get install -yq --no-install-recommends xz-utils ca-certificates \
        pkg-config libsqlite3-dev \
        clang make curl git && \
    rm -rf /var/lib/apt/lists/*

# install minisig
RUN curl --fail -sSL --retry 3 --retry-delay 2 -O https://github.com/jedisct1/minisign/releases/download/${MINISIG}/minisign-${MINISIG}-linux.tar.gz && \
    tar xzf minisign-${MINISIG}-linux.tar.gz -C /

WORKDIR /app
COPY . .

# install zig
RUN ZIG=$(grep '\.minimum_zig_version = "' "build.zig.zon" | cut -d'"' -f2) && \
    case $TARGETPLATFORM in \
      "linux/arm64") ARCH="aarch64" ;; \
      *) ARCH="x86_64" ;; \
    esac && \
    curl --fail -L --retry 3 --retry-delay 2 -O https://ziglang.org/download/${ZIG}/zig-${ARCH}-linux-${ZIG}.tar.xz && \
    curl --fail -L --retry 3 --retry-delay 2 -O https://ziglang.org/download/${ZIG}/zig-${ARCH}-linux-${ZIG}.tar.xz.minisig && \
    /minisign-linux/${ARCH}/minisign -Vm zig-${ARCH}-linux-${ZIG}.tar.xz -P ${ZIG_MINISIG} && \
    tar xf zig-${ARCH}-linux-${ZIG}.tar.xz && \
    mv zig-${ARCH}-linux-${ZIG} /usr/local/lib && \
    ln -s /usr/local/lib/zig-${ARCH}-linux-${ZIG}/zig /usr/local/bin/zig

# build release
RUN zig build -Doptimize=ReleaseFast

FROM debian:stable-slim AS tini-stage
RUN apt-get update -yq && \
    apt-get install -yq --no-install-recommends tini && \
    rm -rf /var/lib/apt/lists/*

FROM debian:stable-slim

RUN apt-get update -yq && \
    apt-get install -yq --no-install-recommends libsqlite3-0 && \
    rm -rf /var/lib/apt/lists/*

# copy ca certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

COPY --from=builder /app/zig-out/bin/zigbin /bin/zigbin
COPY --from=tini-stage /usr/bin/tini /usr/bin/tini

RUN mkdir -p /app/data
ENV ZIGBIN_DB_PATH=/app/data/zigbin.db

EXPOSE 5882/tcp

# Using "tini" as PID1 ensures that signals work as expected, so e.g. "docker stop" will not hang.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/bin/zigbin"]

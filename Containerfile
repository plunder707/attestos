# Build context for scripts and files, never copied into the final image.
FROM scratch AS ctx
COPY build_files /
COPY system_files /system_files

# Bazzite is the base on purpose. It is Fedora-derived, which is the family
# currently blocked by anti-cheat whitelists, so proving attestation here is
# the case worth proving. Building on SteamOS would demonstrate nothing,
# because SteamOS is already allowed.
FROM ghcr.io/ublue-os/bazzite:stable

RUN --mount=type=bind,from=ctx,source=/,target=/ctx \
    --mount=type=cache,dst=/var/cache \
    --mount=type=cache,dst=/var/log \
    --mount=type=tmpfs,dst=/tmp \
    /ctx/build.sh

RUN bootc container lint

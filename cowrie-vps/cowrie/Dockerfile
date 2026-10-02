# Custom Cowrie image: the official image + our bait baked into Cowrie's
# fake filesystem. Build context is cowrie-vps/ (see docker-compose.yml).
#
# Pinned version, never :latest - an unreviewed upstream update can change
# paths or defaults underneath you. To upgrade: change COWRIE_VERSION,
# rebuild, and re-test (setup guide, Step 10).
ARG COWRIE_VERSION=3.0.9

FROM cowrie/cowrie:${COWRIE_VERSION} AS cowrie-base

# ---- Stage 1: embed the bait files into a copy of Cowrie's fs.pickle ----
# The official image is "distroless" (no shell), so this work happens in an
# ordinary Python image and only the finished pickle is copied across.
FROM python:3.12-slim AS bait-builder
WORKDIR /build
COPY --from=cowrie-base /cowrie/cowrie-git/src/cowrie/data/fs.pickle base-fs.pickle
COPY cowrie/build_fs_pickle.py cowrie/honeyfs-manifest.txt ./
COPY cowrie-honeyfs/ honeyfs/
# REQUIRE_BAIT=false (used by the local dev stack) builds even when the bait
# files haven't been copied in. Production always uses the default: true.
ARG REQUIRE_BAIT=true
RUN if [ "$REQUIRE_BAIT" = "true" ]; then MANIFEST=honeyfs-manifest.txt; else MANIFEST=/dev/null; fi \
 && python build_fs_pickle.py base-fs.pickle honeyfs "$MANIFEST" fs.pickle

# ---- Stage 2: the image that actually runs ----
FROM cowrie-base
COPY --from=bait-builder --chown=999:999 /build/fs.pickle /cowrie/custom/fs.pickle

# Safety-critical settings are baked in so they apply even if someone runs
# this image without our docker-compose.yml. (Cowrie reads any config key
# from COWRIE_<SECTION>_<KEY> environment variables.)
ENV COWRIE_SHELL_FILESYSTEM=/cowrie/custom/fs.pickle \
    COWRIE_SSH_FORWARDING=false \
    COWRIE_SSH_FORWARD_REDIRECT=false \
    COWRIE_SSH_FORWARD_TUNNEL=false \
    COWRIE_SSH_SFTP_ENABLED=false \
    COWRIE_TELNET_ENABLED=false

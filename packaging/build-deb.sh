#!/bin/sh
# Build from a copy so dpkg-buildpackage never cleans the developer's checkout.
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output=${1:-"$repo/target/debian"}
mkdir -p "$output"
output=$(CDPATH= cd -- "$output" && pwd)
engine=${CONTAINER_ENGINE:-podman}
image=localhost/netbox-dns-zone-publisher-debian-build
"$engine" build -t "$image" -f "$repo/packaging/Containerfile.debian" "$repo/packaging"
"$engine" run --rm \
    -v "$repo:/source:ro" -v "$output:/output:rw" \
    "$image" sh -ec '
        cp /source/Cargo.toml /source/Cargo.lock /source/LICENSE /source/README.md .
        cp -r /source/src /source/tests /source/examples /source/docs /source/debian /source/packaging .
        cargo fetch --locked
        dpkg-buildpackage -us -uc -b
        lintian --fail-on error ../*.changes
        cp ../*.deb ../*.buildinfo ../*.changes /output/
    '

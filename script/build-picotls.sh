#!/bin/bash
set -eu

PICOTLS_VERSION="${PICOTLS_VERSION:-master}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BUILD_DIR="${BUILD_DIR:-/tmp/picotls-build}"

if command -v picotls >/dev/null 2>&1; then
  echo "picotls already installed: $(which picotls)"
  exit 0
fi

echo "Building picotls (${PICOTLS_VERSION})..."

apt-get update -qq
apt-get install -y -qq cmake libssl-dev pkg-config

rm -rf "${BUILD_DIR}"
git clone --recursive --depth 1 -b "${PICOTLS_VERSION}" https://github.com/h2o/picotls.git "${BUILD_DIR}"
cd "${BUILD_DIR}"
cmake -DCMAKE_INSTALL_PREFIX=/usr/local .
make -j"$(nproc)" cli
cp cli/cli "${INSTALL_DIR}/picotls"
chmod +x "${INSTALL_DIR}/picotls"

echo "picotls installed to ${INSTALL_DIR}/picotls"
picotls -h 2>&1 | head -3

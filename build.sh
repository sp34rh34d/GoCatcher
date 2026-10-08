#!/usr/bin/env bash
# Compila GoCatcher para todos los sistemas operativos soportados.
# Los binarios se generan en dist/.
set -euo pipefail

APP="gocatcher"
VERSION="${VERSION:-1.0}"
OUT="dist"

# Pares GOOS/GOARCH a compilar.
TARGETS=(
  "linux/amd64"
  "linux/arm64"
  "linux/arm"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
  "windows/arm64"
  "freebsd/amd64"
)

rm -rf "$OUT"
mkdir -p "$OUT"

for t in "${TARGETS[@]}"; do
  GOOS="${t%/*}"
  GOARCH="${t#*/}"
  name="${APP}-${VERSION}-${GOOS}-${GOARCH}"
  [ "$GOOS" = "windows" ] && name="${name}.exe"

  echo ">> building ${GOOS}/${GOARCH}"
  CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
    go build -trimpath -ldflags "-s -w" -o "$OUT/$name" .
done

echo ""
echo "Binarios generados en $OUT/:"
ls -lh "$OUT"

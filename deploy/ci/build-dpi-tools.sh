#!/usr/bin/env bash
# Собирает зафиксированную версию независимого классификатора для CI.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NDPI_REVISION="375f99ef9fb4999d778b57bbeece171b3fa9fba6"
NDPI_TAG="5.0"
NDPI_DIR="${AIVPN_NDPI_DIR:-$REPO/target/dpi-tools/ndpi}"
NDPI_GIT=(git --git-dir="$NDPI_DIR/.git" --work-tree="$NDPI_DIR")
mkdir -p "$NDPI_DIR"
# Кеш Cargo может оставить пустые каталоги .git. Восстанавливаем метаданные
# и явно задаем git-dir, чтобы Git не использовал репозиторий приложения.
"${NDPI_GIT[@]}" init -q
if [ "$("${NDPI_GIT[@]}" rev-parse --verify 'HEAD^{commit}' 2>/dev/null || true)" != "$NDPI_REVISION" ]; then
    # Именованный ref доступен через upload-pack; временный сбой повторяем.
    for attempt in 1 2 3; do
        if "${NDPI_GIT[@]}" fetch --depth 1 --no-tags https://github.com/ntop/nDPI.git "refs/tags/$NDPI_TAG"; then
            break
        fi
        if [ "$attempt" -eq 3 ]; then
            echo "dpi-tools: не удалось загрузить nDPI $NDPI_TAG после трех попыток" >&2
            exit 1
        fi
        sleep "$((attempt * 2))"
    done
    # Перенос тега не должен незаметно менять версию классификатора.
    if [ "$("${NDPI_GIT[@]}" rev-parse 'FETCH_HEAD^{commit}')" != "$NDPI_REVISION" ]; then
        echo "dpi-tools: тег nDPI $NDPI_TAG не совпадает с закрепленным SHA" >&2
        exit 1
    fi
    "${NDPI_GIT[@]}" checkout --detach "$NDPI_REVISION"
fi
(cd "$NDPI_DIR" && ./autogen.sh && ./configure && make -j"${BUILD_JOBS:-2}")

#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/scripts" "${TMP_DIR}/go-api/cmd/probe" "${TMP_DIR}/.local/go/bin"
cp "${REPO_ROOT}/scripts/appctl" "${TMP_DIR}/scripts/appctl"
cat > "${TMP_DIR}/.local/go/bin/go" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "version" ]]; then
  echo 'go version go1.25.0 linux/amd64'
elif [[ "${1:-}" == "build" ]]; then
  mkdir -p "$(dirname "$3")"
  printf '%s\n' "${GOOS:-native}/${GOARCH:-native}:${4}" > "$3"
fi
EOF
chmod +x "${TMP_DIR}/.local/go/bin/go"
GO_BIN="${TMP_DIR}/.local/go/bin/go" bash "${TMP_DIR}/scripts/appctl" build
for arch in amd64 arm64; do
  artifact="${TMP_DIR}/storage/probe/forest-probe-linux-${arch}"
  [[ "$(cat "${artifact}")" == "linux/${arch}:./cmd/probe" ]]
  (cd "${TMP_DIR}/storage/probe" && sha256sum -c "$(basename "${artifact}").sha256")
done
GO_BIN="${TMP_DIR}/.local/go/bin/go" bash "${TMP_DIR}/scripts/appctl" build-probe
echo 'probe build and checksums passed'

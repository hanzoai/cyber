#!/usr/bin/env bash

set -Eeuo pipefail

readonly REPO="${HANZO_CYBER_REPO:-hanzoai/cyber}"
version="${HANZO_CYBER_VERSION:-latest}"
install_dir="${HANZO_CYBER_INSTALL_DIR:-$HOME/.local/bin}"
install_probe=true
mode="install"

usage() {
  cat <<'EOF'
Hanzo Cyber installer — verified native binary downloader (macOS & Linux, arm64/amd64)

Usage:
  install.sh [--version vX.Y.Z|latest] [--dir PATH] [--no-probe]
  install.sh --uninstall [--dir PATH]

Options:
  --version TAG   Release tag to install (default: latest)
  --dir PATH      Destination bin directory (default: ~/.local/bin)
  --no-probe      Install only the Go `cyber` binary (skip Rust `cyber-probe`)
  --uninstall     Remove `cyber` and `cyber-probe` from the destination directory
  -h, --help      Show this help message

Environment overrides:
  HANZO_CYBER_REPO, HANZO_CYBER_VERSION, HANZO_CYBER_INSTALL_DIR
EOF
}

die() {
  printf 'cyber-install: %s\n' "$*" >&2
  exit 1
}

log() {
  printf 'cyber-install: %s\n' "$*"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    die "neither sha256sum nor shasum is available to verify downloads"
  fi
}

detect_os() {
  case "$(uname -s)" in
    Darwin) printf 'darwin' ;;
    Linux) printf 'linux' ;;
    *) die "unsupported operating system: $(uname -s)" ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'amd64' ;;
    arm64|aarch64) printf 'arm64' ;;
    *) die "unsupported CPU architecture: $(uname -m)" ;;
  esac
}

verify_checksum() {
  local sums_file="$1"
  local asset_name="$2"
  local downloaded_file="$3"

  local expected
  expected="$(awk -v name="$asset_name" '$2 == name || $2 == "*" name { print $1; exit }' "$sums_file")"
  [[ -n "$expected" ]] || die "checksum for '${asset_name}' not found in SHA256SUMS (fail-closed)"

  local actual
  actual="$(sha256_file "$downloaded_file")"
  if [[ "$actual" != "$expected" ]]; then
    die "SHA-256 mismatch for ${asset_name}: expected ${expected}, got ${actual}"
  fi
  log "verified SHA-256 for ${asset_name} (${actual:0:12}…)"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      [[ $# -ge 2 ]] || die "--version requires a value"
      version="$2"
      shift 2
      ;;
    --dir)
      [[ $# -ge 2 ]] || die "--dir requires a value"
      install_dir="$2"
      shift 2
      ;;
    --no-probe)
      install_probe=false
      shift
      ;;
    --uninstall)
      mode="uninstall"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

if [[ "$mode" == "uninstall" ]]; then
  rm -f "${install_dir}/cyber" "${install_dir}/cyber-probe"
  log "removed cyber binaries from ${install_dir}"
  exit 0
fi

require_cmd curl

os="$(detect_os)"
arch="$(detect_arch)"

if [[ "$version" == "latest" ]]; then
  base_url="https://github.com/${REPO}/releases/latest/download"
else
  [[ "$version" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.]+)?$ ]] || die "invalid version tag: ${version}"
  tag="$version"
  [[ "$tag" == v* ]] || tag="v${tag}"
  base_url="https://github.com/${REPO}/releases/download/${tag}"
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

sums_file="${tmp_dir}/SHA256SUMS"
log "downloading SHA256SUMS from ${base_url}"
curl -fsSL -o "$sums_file" "${base_url}/SHA256SUMS" || die "failed to download SHA256SUMS from ${base_url}"

mkdir -p "$install_dir"

cyber_asset="cyber-${os}-${arch}"
cyber_tmp="${tmp_dir}/${cyber_asset}"
log "downloading ${cyber_asset}"
curl -fsSL -o "$cyber_tmp" "${base_url}/${cyber_asset}" || die "failed to download ${cyber_asset}"
verify_checksum "$sums_file" "$cyber_asset" "$cyber_tmp"
install -m 0755 "$cyber_tmp" "${install_dir}/cyber"

if [[ "$install_probe" == true ]]; then
  probe_asset="cyber-probe-${os}-${arch}"
  probe_tmp="${tmp_dir}/${probe_asset}"
  if grep -Eq "[[:space:]]\*?${probe_asset}$" "$sums_file"; then
    log "downloading ${probe_asset}"
    curl -fsSL -o "$probe_tmp" "${base_url}/${probe_asset}" || die "failed to download ${probe_asset}"
    verify_checksum "$sums_file" "$probe_asset" "$probe_tmp"
    install -m 0755 "$probe_tmp" "${install_dir}/cyber-probe"
  else
    log "${probe_asset} not listed in release SHA256SUMS; skipping optional probe binary"
  fi
fi

log "installed Hanzo Cyber to ${install_dir}"
if [[ ":${PATH}:" != *":${install_dir}:"* ]]; then
  printf '\nAdd %s to your PATH:\n  export PATH="%s:%s"\n' "$install_dir" "$install_dir" "\$PATH"
fi
printf '\nVerify installation:\n  %s/cyber version\n  %s/cyber doctor\n' "$install_dir" "$install_dir"

#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${1:-} == --package ]]; then
  shift
  exec bash "$(dirname -- "${BASH_SOURCE[0]}")/package.sh" "$@"
fi

if (( $# != 1 )); then
  printf 'Usage: %s /path/to/nginx.conf\n' "$0" >&2
  exit 2
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
if [[ ! -f "$1" ]]; then
  printf 'nginx config not found: %s\n' "$1" >&2
  exit 1
fi
config_file="$(realpath -e -- "$1")"

patches=(
  CVE-2026-42533-pre1.patch
  CVE-2026-42533-1.patch
  CVE-2026-42533-2-1.25.5.patch
  CVE-2026-42533-3.patch
  CVE-2026-42533-4.patch
)
for patch_name in "${patches[@]}"; do
  if [[ ! -f "$script_dir/patches/$patch_name" ]]; then
    printf 'Patch not found: %s\n' "$script_dir/patches/$patch_name" >&2
    exit 1
  fi
done

if ! command -v apt-get >/dev/null; then
  printf 'This build requires apt-get.\n' >&2
  exit 1
fi
if (( EUID == 0 )); then
  as_root=()
else
  if ! command -v sudo >/dev/null; then
    printf 'This build requires sudo when run as a non-root user.\n' >&2
    exit 1
  fi
  as_root=(sudo)
fi

source_url='https://nginx.org/download/nginx-1.25.5.tar.gz'
source_sha256='2fe2294f8af4144e7e842eaea884182a84ee7970e11046ba98194400902bbec0'
install_prefix='/usr/local/nginx'
installed_bin='/usr/local/sbin/nginx'

"${as_root[@]}" apt-get update
"${as_root[@]}" apt-get install -y --no-install-recommends \
  build-essential ca-certificates curl patch libpcre2-dev zlib1g-dev libssl-dev

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/nginx-1.25.5-build.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT
archive="$work_dir/nginx-1.25.5.tar.gz"

curl --fail --location --show-error --silent --retry 3 \
  --output "$archive" "$source_url"
printf '%s  %s\n' "$source_sha256" "$archive" | sha256sum -c -
tar -xzf "$archive" -C "$work_dir"
cd "$work_dir/nginx-1.25.5"

for patch_name in "${patches[@]}"; do
  fuzz=0
  if [[ "$patch_name" == CVE-2026-42533-2-1.25.5.patch ]]; then
    fuzz=1
  fi
  patch -p1 --batch --forward --fuzz="$fuzz" < "$script_dir/patches/$patch_name"
done

./configure \
  --prefix="$install_prefix" \
  --sbin-path="$installed_bin" \
  --conf-path=conf/nginx.conf \
  --pid-path=logs/nginx.pid \
  --error-log-path=logs/error.log \
  --http-log-path=logs/access.log \
  --with-http_ssl_module \
  --with-http_v2_module \
  --with-pcre-jit

make -j2
mkdir -p "$work_dir/runtime/logs"
./objs/nginx -t -p "$work_dir/runtime/" -c "$config_file" -e stderr

"${as_root[@]}" make install
"${as_root[@]}" "$installed_bin" -t -p "$install_prefix/" -c "$config_file" -e stderr

pid_file="$install_prefix/logs/nginx.pid"
if [[ -f "$pid_file" ]]; then
  "${as_root[@]}" "$installed_bin" -s quit -p "$install_prefix/" -c "$config_file"
  for (( attempt = 0; attempt < 50 && -e "$pid_file"; attempt++ )); do
    sleep 0.1
  done
  if [[ -e "$pid_file" ]]; then
    printf 'Previous patched nginx did not stop: %s\n' "$pid_file" >&2
    exit 1
  fi
fi

"${as_root[@]}" "$installed_bin" -p "$install_prefix/" -c "$config_file"
printf 'Started %s with %s\n' "$installed_bin" "$config_file"

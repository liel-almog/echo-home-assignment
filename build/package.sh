#!/usr/bin/env bash
set -Eeuo pipefail

if (( $# != 1 )); then
  printf 'Usage: %s OUTPUT_DIR\n' "$0" >&2
  exit 2
fi

# Variable
install -d "$1"
output_dir="$(cd -- "$1" && pwd -P)"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
version=1.25.5
revision='1+echo1'
source_url="https://nginx.org/download/nginx-${version}.tar.gz"
source_sha256=2fe2294f8af4144e7e842eaea884182a84ee7970e11046ba98194400902bbec0
patches=(
  CVE-2026-42533-pre1.patch
  CVE-2026-42533-1.patch
  CVE-2026-42533-2-1.25.5.patch
  CVE-2026-42533-3.patch
  CVE-2026-42533-4.patch
)

# Check every build tool exists
for program in curl sha256sum tar patch make dpkg dpkg-query dpkg-deb; do
  command -v "$program" >/dev/null || {
    printf 'Missing build tool: %s\n' "$program" >&2
    exit 1
  }
done

# SSL versions
ssl_package=
ssl_version=
architecture="$(dpkg --print-architecture)"
for candidate in libssl3t64 libssl3; do
  if package_record="$(dpkg-query -W -f='${db:Status-Status} ${Version}' "${candidate}:${architecture}" 2>/dev/null)" \
    && [[ $package_record == installed\ * ]]; then
    ssl_package=$candidate
    ssl_version=${package_record#installed }
    break
  fi
done

if [[ -z $ssl_package ]]; then
  printf 'Neither libssl3 nor libssl3t64 is installed. Install libssl-dev first.\n' >&2
  exit 1
fi

case $ssl_package in
  libssl3) fixed_ssl_version='3.0.14-1~deb12u2' ;;
  libssl3t64) fixed_ssl_version='3.3.2-1' ;;
esac

if ! dpkg --compare-versions "$ssl_version" ge "$fixed_ssl_version"; then
  printf '%s %s is older than the required version %s\n' \
    "$ssl_package" "$ssl_version" "$fixed_ssl_version" >&2
  exit 1
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/nginx-package.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT
archive="$work_dir/nginx-${version}.tar.gz"

# install , build and patch from source
curl --fail --location --show-error --silent --retry 3 \
  --output "$archive" "$source_url"
printf '%s  %s\n' "$source_sha256" "$archive" | sha256sum --check -
tar -xzf "$archive" -C "$work_dir"
cd "$work_dir/nginx-${version}"

for patch_name in "${patches[@]}"; do
  patch_file="$script_dir/patches/$patch_name"
  [[ -f "$patch_file" ]] || {
    printf 'Missing patch: %s\n' "$patch_file" >&2
    exit 1
  }
  fuzz=0
  if [[ "$patch_name" == CVE-2026-42533-2-1.25.5.patch ]]; then
    # This backport has one older grpc context line in nginx 1.25.5.
    fuzz=1
  fi
  printf 'Applying %s\n' "$patch_name"
  patch --batch --forward --fuzz="$fuzz" -p1 < "$patch_file"
done
printf 'Applied all %d security patches to nginx %s source\n' "${#patches[@]}" "$version"

# configure
./configure \
  --prefix=/etc/nginx \
  --sbin-path=/usr/sbin/nginx \
  --modules-path=/usr/lib/nginx/modules \
  --conf-path=/etc/nginx/nginx.conf \
  --pid-path=/run/nginx.pid \
  --lock-path=/run/lock/nginx.lock \
  --error-log-path=/var/log/nginx/error.log \
  --http-log-path=/var/log/nginx/access.log \
  --http-client-body-temp-path=/var/cache/nginx/client_temp \
  --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
  --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
  --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
  --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
  --user=nginx \
  --group=nginx \
  --with-http_ssl_module \
  --with-http_v2_module \
  --with-stream \
  --with-stream_ssl_module \
  --with-pcre-jit

make -j2

package_root="$work_dir/package"
install -d "$package_root/DEBIAN" "$package_root/usr/sbin" \
  "$package_root/etc/nginx/html" "$package_root/usr/share/nginx/html" \
  "$package_root/usr/share/doc/nginx-echo" \
  "$package_root/var/log/nginx" "$package_root/var/cache/nginx"
install -m 755 objs/nginx "$package_root/usr/sbin/nginx"
install -m 644 conf/nginx.conf conf/mime.types conf/fastcgi_params \
  conf/scgi_params conf/uwsgi_params "$package_root/etc/nginx/"
install -m 644 html/index.html html/50x.html "$package_root/etc/nginx/html/"
install -m 644 html/index.html html/50x.html "$package_root/usr/share/nginx/html/"
install -m 644 LICENSE "$package_root/usr/share/doc/nginx-echo/copyright"

cat > "$package_root/DEBIAN/control" <<EOF
Package: nginx
Version: ${version}-${revision}
Architecture: ${architecture}
Maintainer: Echo home assignment <noreply@example.invalid>
Depends: libc6 (>= 2.36), libcrypt1, libpcre2-8-0, zlib1g, ${ssl_package} (>= ${fixed_ssl_version})
Conflicts: nginx-common, nginx-core, nginx-full, nginx-light, nginx-extras
Replaces: nginx-common, nginx-core, nginx-full, nginx-light, nginx-extras
Description: nginx ${version} with CVE-2026-42533 backport
 nginx built from the pinned upstream source with the supplied security patches.
 Requires the Bookworm OpenSSL update for CVE-2024-6119.
EOF

find "$package_root/etc/nginx" -type f -printf '/etc/nginx/%P\n' \
  > "$package_root/DEBIAN/conffiles"

package_file="$output_dir/nginx_${version}-${revision}_${architecture}.deb"
dpkg-deb --build --root-owner-group "$package_root" "$package_file"
dpkg-deb --info "$package_file"
printf 'Built %s\n' "$package_file"

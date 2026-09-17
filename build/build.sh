sudo apt update
sudo apt install -y gcc make
sudo apt update
sudo apt install -y build-essential libpcre2-dev zlib1g-dev libssl-dev
sudo apt install -y build-essential libpcre2-dev zlib1g zlib1g-dev libssl-dev libgd-dev libxml2 libxml2-dev uuid-dev

nginx -s quit
sudo nginx -s stop
sudo systemctl stop nginx
sudo pkill nginx

rm -rf nginx-release-1.25.5
wget -O release-1.25.5.tar.gz https://github.com/nginx/nginx/archive/refs/tags/release-1.25.5.tar.gz
tar -zxvf release-1.25.5.tar.gz
cd nginx-release-1.25.5

patch -p1 < ../patches/CVE-2026-42533-pre1.patch
patch -p1 < ../patches/CVE-2026-42533-1.patch
patch -p1 < ../patches/CVE-2026-42533-2-1.25.5.patch
patch -p1 < ../patches/CVE-2026-42533-3.patch
patch -p1 < ../patches/CVE-2026-42533-4.patch

auto/configure \
  --prefix=/usr/local/nginx \
  --sbin-path=/usr/local/sbin/nginx \
  --conf-path=/etc/nginx/nginx.conf \
  --pid-path=/run/nginx.pid \
  --error-log-path=/var/log/nginx/error.log \
  --http-log-path=/var/log/nginx/access.log \
  --with-http_ssl_module \
  --with-http_v2_module \
  --with-pcre-jit

make -j2
sudo make install

sudo ln -sf /usr/local/sbin/nginx /usr/bin/nginx
hash -r

sudo nginx -t -c /home/liela/projects/echo/nginx.conf

sudo nginx -c /home/liela/projects/echo/nginx.conf

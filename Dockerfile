FROM nginx:1.25-bookworm AS upstream

FROM debian:bookworm-slim AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential ca-certificates curl dpkg-dev libpcre2-dev \
       libssl-dev patch zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY build/ /work/build/
# Copy only configuration and static content from upstream. nginx itself is built below.
COPY --from=upstream /etc/nginx/ /work/upstream/etc/nginx/
COPY --from=upstream /usr/share/nginx/html/ /work/upstream/usr/share/nginx/html/
RUN bash /work/build/build.sh --package /out /work/upstream

FROM scratch AS artifact
COPY --from=builder /out/ /

FROM debian:bookworm-slim AS runtime
LABEL maintainer="NGINX Docker Maintainers <docker-maint@nginx.com>"
ENV NGINX_VERSION=1.25.5 \
    NJS_VERSION=0.8.4 \
    NJS_RELEASE=3~bookworm \
    PKG_RELEASE=1~bookworm

RUN groupadd --system --gid 101 nginx \
    && useradd --system --gid nginx --no-create-home --home /nonexistent \
       --comment "nginx user" --shell /bin/false --uid 101 nginx

COPY --from=builder /out/ /tmp/nginx-package/
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       /tmp/nginx-package/*.deb gettext-base curl \
    && rm -rf /var/lib/apt/lists/* /tmp/nginx-package \
    && ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log \
    && nginx -t

COPY --from=upstream /docker-entrypoint.sh /docker-entrypoint.sh
COPY --from=upstream /docker-entrypoint.d/ /docker-entrypoint.d/

ENTRYPOINT ["/docker-entrypoint.sh"]
EXPOSE 80
STOPSIGNAL SIGQUIT
CMD ["nginx", "-g", "daemon off;"]

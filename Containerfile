FROM nginx:1.25-bookworm AS upstream

FROM debian:bookworm-slim
LABEL maintainer="NGINX Docker Maintainers <docker-maint@nginx.com>"
ENV NGINX_VERSION=1.25.5 \
    PKG_RELEASE=1~bookworm

RUN groupadd --system --gid 101 nginx \
    && useradd --system --gid nginx --no-create-home --home /nonexistent \
    --comment "nginx user" --shell /bin/false --uid 101 nginx

COPY dist/nginx_1.25.5-1+echo1_*.deb /tmp/nginx-package/
RUN test "$(find /tmp/nginx-package -maxdepth 1 -name '*.deb' | wc -l)" -eq 1 \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
    /tmp/nginx-package/*.deb \
    && rm -rf /var/lib/apt/lists/* /tmp/nginx-package \
    && ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log \
    && chown -R nginx:nginx /var/cache/nginx \
    && nginx -t

COPY --from=upstream /docker-entrypoint.sh    /docker-entrypoint.sh
COPY --from=upstream /docker-entrypoint.d     /docker-entrypoint.d

ENTRYPOINT ["/docker-entrypoint.sh"]
EXPOSE 80
STOPSIGNAL SIGQUIT
CMD ["nginx", "-g", "daemon off;"]

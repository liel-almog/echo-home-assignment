FROM nginx:1.31.6

RUN mkdir /logs && touch /logs/nginx.pid && touch /logs/error.log

COPY ../nginx.conf /etc/nginx/nginx.conf


EXPOSE 8950

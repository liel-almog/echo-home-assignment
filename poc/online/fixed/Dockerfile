FROM nginx-echo:1.25.5

RUN mkdir /logs && touch /logs/nginx.pid && touch /logs/error.log

COPY nginx.conf /etc/nginx/nginx.conf


EXPOSE 8950

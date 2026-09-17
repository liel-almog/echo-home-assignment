FROM nginx:1.25-bookworm

RUN mkdir /logs && touch /logs/nginx.pid && touch /logs/error.log
RUN apt update
RUN apt install -y python3

COPY nginx.conf /etc/nginx/nginx.conf

COPY poc.py /src/app/poc.py

EXPOSE 8950

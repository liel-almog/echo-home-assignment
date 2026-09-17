FROM nginx:1.25-bookworm

RUN mkdir /logs && touch /logs/nginx.pid && touch /logs/error.log
RUN apt update && apt -y install python3 python3-pip python3-venv
COPY nginx.conf /etc/nginx/nginx.conf


EXPOSE 8950

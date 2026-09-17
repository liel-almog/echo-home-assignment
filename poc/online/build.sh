sudo docker build -t online-cve-2026-42533-nginx .
sudo docker run -it --rm --name online-cve-2026-42533-nginx -p 127.0.0.1:8950:8950 cve-2026-42533-nginx

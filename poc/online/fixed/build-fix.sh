sudo docker build -t online-cve-2026-42533-nginx:fixed -f Dockerfile.good .
sudo docker run -it --rm --name online-cve-2026-42533-nginx-fixed -p 127.0.0.1:8950:8950 online-cve-2026-42533-nginx:fixed

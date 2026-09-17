#!/usr/bin/env bash
set -Eeuo pipefail

docker build -t online-cve-2026-42533-nginx:fixed .
docker run -it --rm --name online-cve-2026-42533-nginx-fixed \
  -p 127.0.0.1:8950:8950 online-cve-2026-42533-nginx:fixed

# Home assinment

## Choosing CVEs

### CVE-2026-31789

This is a CVE in libgnutls30 - this is the main GNU library used for SSL/TLS. The vulnerability allows an attacker to perform a Denial of Service (DoS) attack by sending a specially crafted malformed fragments with zero length and non-zero offset, leading to an integer underflow. This can cause an out-of-bounds read.

To check if the CVE is present in the docker image, you can run the following commands:

```bash
docker run -it --rm nginx:1.25-bookworm ldd $(which curl) | grep gnutls
```

| ID             | Severity | Fix Method | Evidence Link | Reason                                                 |
| -------------- | -------- | ---------- | ------------- | ------------------------------------------------------ |
| CVE-2026-31789 | CRITICAL |            | v             | CVE in libgnutls30 - main GNU library used for SSL/TLS |
|                |          |            |
|                |          |            |

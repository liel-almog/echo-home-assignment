# Home assinment

## AI

Using codex in the IDE. Have registered to OpenAI cyber and got approved.

## Choosing CVEs

### CVEs within a dependenty

This is a CVE in libssl3 - The reason of choosing this CVE is because this is the highest CVE (the other one was only on 32-bit systems) and grype gave it the highest chance of explotation

To check if the CVE is present in the docker image, you can run the following commands:

```bash
docker run -it --rm nginx:1.25-bookworm ldd $(which nginx) | grep libssl
```

### CVE from an upstream version

Go to `https://nginx.org/en/security_advisories.html` and search for `major` vulnerability and look for ones that affect the version we are at (1.25.x)

| ID             | Severity | Fix Method   | Evidence Link                                   | Reason                                                                                              |
| -------------- | -------- | ------------ | ----------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| CVE-2024-6119  | HIGH     | Version Bump | https://avd.aquasec.com/nvd/cve-2024-6119       | CVE in libssl3 - Possible denial of service in X.509 name checks                                    |
| CVE-2026-42533 | CRITICAL | backporting  | https://nvd.nist.gov/vuln/detail/cve-2026-42533 | CVE in nginx - that allows an attacker restart the server or if ASLR is disabled then allows an RCE |

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

## Build the patched Debian package

Run `make build` from the repository root. The Dockerfile starts with a fresh
`debian:bookworm-slim` image, installs build tools, and calls
`build/build.sh --package /out /work/upstream`. The package script downloads the pinned nginx
1.25.5 source, verifies its SHA-256, applies the five CVE-2026-42533 patches in
order, compiles nginx, and creates `dist/nginx_1.25.5-1+echo1_<arch>.deb`.
The final image stage exports only that `.deb`; it contains no build tools.
The Makefile extracts the build result into `dist/` as the invoking user.

Run `make image` to build `nginx-echo:1.25.5`. Its final stage starts from
`debian:bookworm-slim`, installs the source-built `.deb` and runtime tools, and
copies the official `nginx:1.25-bookworm` entrypoint scripts. The `.deb` packages
the official image's configuration and static HTML as conffiles and data, while
the nginx executable is compiled from the pinned source. The runtime image uses
the official port 80, root process, default working directory, entrypoint,
command, and SIGQUIT stop signal.

The package depends on `libssl3 >= 3.0.14-1~deb12u2`, the Debian Bookworm fix
for CVE-2024-6119. It includes the nginx binary, default configuration, and
default HTML files. It does not install or start a service. The existing
`build/build.sh /path/to/nginx.conf` mode remains available for a local source
build and run.

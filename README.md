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

Run `make build` from the repository root. `build/Dockerfile.build` starts with
a fresh `debian:bookworm-slim` builder, installs build tools, and calls
`build/build.sh --package /out`. The package script downloads the
pinned nginx 1.25.5 source, verifies its SHA-256 hash, applies the five
CVE-2026-42533 patches in order, and compiles nginx. It creates
`dist/nginx_1.25.5-1+echo1_<arch>.deb`. The `artifact` stage exports only that
`.deb`; it contains no build tools. The Makefile extracts the build result into
`dist/` as the invoking user. The build Dockerfile's ignore file excludes
existing `dist/` artifacts from the builder context.

Run `make image` to rebuild the `.deb` and then build `nginx-echo:1.25.5` from
`Containerfile`. The runtime build starts from `debian:bookworm-slim`, installs
the `.deb` from `dist/`. No nginx image, binary, configuration, HTML, or
entrypoint is copied from `nginx:1.25-bookworm`: the package uses the nginx
source tree's `conf/` and `html/` files, and the repository supplies the small
entrypoint script. The runtime image exposes port 80, runs nginx as root with
its worker user set to `nginx`, and uses the nginx command and SIGQUIT stop
signal.

To exercise the patched image with the online proof of concept, first run
`make image`, then run `./build-fix.sh` from `poc/online/fixed/`. That
Dockerfile uses `nginx-echo:1.25.5`; `poc/online/Dockerfile` intentionally
uses the vulnerable `nginx:1.25-bookworm` baseline. The proof of concept's
`--crash` mode only reports whether the worker remains available, so it is not
a pass/fail check for the patch. Use the exact vulnerable behavior or exploit
result as the verification criterion. `Containerfile` uses nginx's source
default configuration, so it does not contain the PoC `/l2/` location.
The `--leak` probe now rejects non-200 responses instead of treating a default
site error page as leaked data.

The package depends on `libssl3 >= 3.0.14-1~deb12u2`, the Debian Bookworm fix
for CVE-2024-6119. It includes the nginx binary, default configuration, and
default HTML files. It does not install or start a service. The existing
`build/build.sh /path/to/nginx.conf` mode remains available for a local source
build and run.

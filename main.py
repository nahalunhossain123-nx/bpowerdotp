#!/usr/bin/env python3
"""
bPOWERd Bulk Signup Tool — Termux/Android edition
- Reads phone numbers from numbers.txt (one per line, with CC, no +)
- Threads: default 5, configurable up to 30
- Each number is used exactly once (thread-safe queue)
- Proxy: dataimpulse rotating proxy
- Solves reCAPTCHA v3 via CaptchaAI per request

Termux quick-start:
    pkg install python -y
    pip install requests
    termux-setup-storage
    python bpowerd.py -t 5
"""

import requests
import struct
import time
import sys
import threading
import queue
import os
import argparse
import signal
from datetime import datetime

# Silence noisy InsecureRequestWarning (some Android CA bundles are odd)
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

# ── UTF-8 stdout (Termux supports this natively; guard for safety) ───────────
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG  (override with env vars — safer on shared Termux sessions)
# ─────────────────────────────────────────────────────────────────────────────
CAPTCHA_AI_KEY    = os.getenv("CAPTCHA_AI_KEY",    "fexcvagf9ad6q3udkrtgq7kw6kjxo5dp")
RECAPTCHA_SITEKEY = os.getenv("RECAPTCHA_SITEKEY", "6Lc1cw4qAAAAAFsbelBAI5cDz0cOpXgdf5PXs0Xi")
TARGET_URL        = os.getenv("TARGET_URL",        "https://bpowerd.com/za/login")
API_URL           = os.getenv("API_URL",           "https://bpowerd.com/api/digitalbutler.v2.auth.Auth/RequestLogin")
BRAND             = os.getenv("BRAND",             "bpowerd_za")

# Proxy (format: user:pass@host:port)
PROXY_RAW = os.getenv(
    "PROXY_RAW",
    "4fbc248b3591ed95b330:a9fbbc8d1ca5ce5e@gw.dataimpulse.com:823",
)
PROXIES = {
    "http":  "http://" + PROXY_RAW,
    "https": "http://" + PROXY_RAW,
}

DEFAULT_THREADS = 5            # Termux/Android: keep low by default
MAX_THREADS     = 30
NUMBERS_FILE    = os.path.expanduser("~/bpowerd/numbers.txt")
RESULTS_FILE    = os.path.expanduser("~/bpowerd/results.txt")

USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 16; Pixel 10) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/156.0.0.0 Mobile Safari/537.36"
)

# ─────────────────────────────────────────────────────────────────────────────
# COLOURS  (Termux supports ANSI natively)
# ─────────────────────────────────────────────────────────────────────────────
RESET   = "\033[0m"
BOLD    = "\033[1m"
GREEN   = "\033[92m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
BLUE    = "\033[94m"
DIM     = "\033[2m"

# ─────────────────────────────────────────────────────────────────────────────
# THREAD-SAFE CONSOLE PRINTER
# ─────────────────────────────────────────────────────────────────────────────
_print_lock = threading.Lock()

def ts():
    return datetime.now().strftime("%H:%M:%S")

def log(tid, phone, msg, level="INFO"):
    time_str = f"{DIM}{ts()}{RESET}"
    tid_str  = f"{DIM}T{tid:02d}{RESET}"

    if level == "OTP_SENT":
        line = f"{time_str} {tid_str} {BOLD}{GREEN}  [+]  OTP Sent to {phone}{RESET}"
    elif level == "FAILED":
        line = f"{time_str} {tid_str} {BOLD}{RED}  [x]  Failed for {phone}  |  {msg}{RESET}"
    elif level == "CAPTCHA":
        line = f"{time_str} {tid_str} {MAGENTA}[CAP]{RESET} {phone:>15s}  {msg}"
    elif level == "WARN":
        line = f"{time_str} {tid_str} {YELLOW}[WRN]{RESET} {phone:>15s}  {msg}"
    else:
        line = f"{time_str} {tid_str} {BLUE}[   ]{RESET} {DIM}{phone:>15s}  {msg}{RESET}"

    with _print_lock:
        try:
            print(line, flush=True)
        except Exception:
            pass

# ─────────────────────────────────────────────────────────────────────────────
# STATS
# ─────────────────────────────────────────────────────────────────────────────
stats_lock   = threading.Lock()
stat_success = 0
stat_fail    = 0
stat_total   = 0

def bump(key):
    global stat_success, stat_fail, stat_total
    with stats_lock:
        if key == "success":
            stat_success += 1
        elif key == "fail":
            stat_fail += 1
        stat_total += 1

def print_stats():
    with stats_lock:
        s, f, t = stat_success, stat_fail, stat_total
    bar = "=" * 60
    print()
    print(f"{CYAN}{bar}{RESET}")
    print(
        f"  {BOLD}FINAL STATS{RESET}  "
        f"total={BOLD}{t}{RESET}  "
        f"{GREEN}{BOLD}sent={s}{RESET}  "
        f"{RED}{BOLD}failed={f}{RESET}"
    )
    print(f"{CYAN}{bar}{RESET}")

# ─────────────────────────────────────────────────────────────────────────────
# RESULTS FILE
# ─────────────────────────────────────────────────────────────────────────────
results_lock = threading.Lock()

def save_result(phone, status, note=""):
    line = f"{datetime.now().isoformat()} | {phone} | {status} | {note}\n"
    try:
        with results_lock:
            with open(RESULTS_FILE, "a", encoding="utf-8") as f:
                f.write(line)
    except Exception as e:
        log(0, phone, f"Could not write results: {e}", "WARN")

# ─────────────────────────────────────────────────────────────────────────────
# PROTOBUF HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def encode_varint(value):
    buf = b""
    while value > 0x7F:
        buf += bytes([(value & 0x7F) | 0x80])
        value >>= 7
    buf += bytes([value])
    return buf

def encode_length_delimited(field_number, payload):
    tag = encode_varint((field_number << 3) | 2)
    return tag + encode_varint(len(payload)) + payload

def build_request_proto(phone_e164):
    phone_bytes = phone_e164.encode("utf-8")
    level1 = encode_length_delimited(1, phone_bytes)
    level2 = encode_length_delimited(3, level1)
    outer  = encode_length_delimited(1, level2)
    return outer

def wrap_grpc_web(proto_bytes):
    header = struct.pack(">BI", 0, len(proto_bytes))
    return header + proto_bytes

# ─────────────────────────────────────────────────────────────────────────────
# CAPTCHAAI SOLVER
# ─────────────────────────────────────────────────────────────────────────────
def solve_recaptcha_v3(tid, phone, api_key, sitekey, pageurl, action="login"):
    log(tid, phone, "Submitting captcha to CaptchaAI ...", "CAPTCHA")

    submit_payload = {
        "key":       api_key,
        "method":    "userrecaptcha",
        "version":   "v3",
        "googlekey": sitekey,
        "pageurl":   pageurl,
        "action":    action,
        "min_score": 0.3,
        "json":      1,
    }

    resp = requests.post(
        "https://ocr.captchaai.com/in.php",
        data=submit_payload,
        timeout=30,
    )
    resp.raise_for_status()
    result = resp.json()

    if result.get("status") != 1:
        raise RuntimeError("CaptchaAI submit failed: " + str(result.get("request")))

    task_id = result["request"]
    log(tid, phone, f"Captcha task {task_id} - waiting ...", "CAPTCHA")

    poll_url = (
        "https://ocr.captchaai.com/res.php"
        "?key=" + api_key +
        "&action=get&id=" + str(task_id) + "&json=1"
    )

    for attempt in range(30):   # up to 150 s
        time.sleep(5)
        try:
            poll = requests.get(poll_url, timeout=30).json()
        except Exception as e:
            log(tid, phone, f"Poll error: {e}", "WARN")
            continue

        if poll.get("status") == 1:
            log(tid, phone, f"Captcha solved (attempt {attempt + 1})", "CAPTCHA")
            return poll["request"]

        req_val = poll.get("request", "")
        if req_val == "CAPCHA_NOT_READY":
            continue

        raise RuntimeError("CaptchaAI error: " + str(req_val))

    raise RuntimeError("CaptchaAI timed out after 150 s.")

# ─────────────────────────────────────────────────────────────────────────────
# SEND REQUEST
# ─────────────────────────────────────────────────────────────────────────────
def send_request(tid, phone_e164, captcha_token):
    grpc_body = wrap_grpc_web(build_request_proto(phone_e164))

    headers = {
        "accept":             "*/*",
        "accept-encoding":    "gzip, deflate, br",
        "accept-language":    "en-US,en;q=0.9",
        "brand":              BRAND,
        "captcha-token":      captcha_token,
        "content-type":       "application/grpc-web+proto",
        "origin":             "https://bpowerd.com",
        "referer":            "https://bpowerd.com/za/login",
        "sec-ch-ua":          '"Not:A-Brand";v="8", "Chromium";v="156", "Google Chrome";v="156"',
        "sec-ch-ua-mobile":   "?1",
        "sec-ch-ua-platform": '"Android"',
        "sec-fetch-dest":     "empty",
        "sec-fetch-mode":     "cors",
        "sec-fetch-site":     "same-origin",
        "user-agent":         USER_AGENT,
        "x-grpc-web":         "1",
    }

    return requests.post(
        API_URL,
        data    = grpc_body,
        headers = headers,
        proxies = PROXIES,
        timeout = 30,
    )

# ─────────────────────────────────────────────────────────────────────────────
# WORKER
# ─────────────────────────────────────────────────────────────────────────────
def worker(tid, number_queue, done_event):
    while not done_event.is_set():
        try:
            phone_raw = number_queue.get_nowait()
        except queue.Empty:
            break

        phone = "+" + phone_raw.strip()
        log(tid, phone, "Starting ...", "INFO")

        try:
            captcha_token = solve_recaptcha_v3(
                tid=tid, phone=phone,
                api_key=CAPTCHA_AI_KEY,
                sitekey=RECAPTCHA_SITEKEY,
                pageurl=TARGET_URL,
                action="login",
            )

            log(tid, phone, "Sending gRPC request ...", "INFO")
            response = send_request(tid, phone, captcha_token)
            raw = response.content

            if response.status_code == 200 and len(raw) >= 5:
                flag   = raw[0]
                length = struct.unpack(">I", raw[1:5])[0]
                data   = raw[5:5 + length]

                offset = 5 + length
                grpc_status = "unknown"
                if offset < len(raw) and raw[offset] == 0x80:
                    t_len  = struct.unpack(">I", raw[offset + 1:offset + 5])[0]
                    t_data = raw[offset + 5:offset + 5 + t_len].decode("utf-8", errors="replace")
                    if "grpc-status: 0" in t_data:
                        grpc_status = "0 (OK)"
                    else:
                        grpc_status = t_data.strip()

                if phone.encode() in data and grpc_status == "0 (OK)":
                    log(tid, phone, "", "OTP_SENT")
                    save_result(phone, "OTP_SENT", f"grpc-status={grpc_status}")
                    bump("success")
                else:
                    reason = f"bad grpc-status: {grpc_status}"
                    log(tid, phone, reason, "FAILED")
                    save_result(phone, "FAILED", f"grpc={grpc_status} hex={raw.hex()[:60]}")
                    bump("fail")
            else:
                reason = f"HTTP {response.status_code}"
                log(tid, phone, reason, "FAILED")
                save_result(phone, "FAILED", f"status={response.status_code}")
                bump("fail")

        except Exception as exc:
            log(tid, phone, str(exc), "FAILED")
            save_result(phone, "FAILED", str(exc))
            bump("fail")

        finally:
            number_queue.task_done()

    log(tid, "-" * 13, "Thread done, queue empty.", "INFO")

# ─────────────────────────────────────────────────────────────────────────────
# LOAD NUMBERS
# ─────────────────────────────────────────────────────────────────────────────
def load_numbers(filepath):
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        print(f"[i] Create it with:  nano {filepath}")
        sys.exit(1)

    numbers, seen = [], set()
    with open(filepath, "r", encoding="utf-8-sig") as f:
        for line in f:
            num = line.strip().lstrip("+")
            if num and num.isdigit() and num not in seen:
                numbers.append(num)
                seen.add(num)
            elif num and not num.isdigit():
                print(f"[!] Skipping invalid line: {repr(line.strip())}")
    return numbers

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="bPOWERd Bulk Signup Tool (Termux edition)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS,
                        metavar="N", help=f"Parallel threads (1–{MAX_THREADS})")
    parser.add_argument("-f", "--file", default=NUMBERS_FILE,
                        metavar="PATH", help="Path to numbers.txt")
    args = parser.parse_args()

    num_threads = max(1, min(args.threads, MAX_THREADS))

    print()
    print(f"{CYAN}{'=' * 60}{RESET}")
    print(f"{CYAN}   bPOWERd Bulk Signup Tool  (Termux/Android){RESET}")
    print(f"{CYAN}{'=' * 60}{RESET}")
    print(f"  Threads  : {num_threads} (max {MAX_THREADS})")
    print(f"  Numbers  : {args.file}")
    print(f"  Results  : {RESULTS_FILE}")
    print(f"  Proxy    : {PROXY_RAW[:30]}...")
    print(f"{CYAN}{'=' * 60}{RESET}")
    print()

    numbers = load_numbers(args.file)
    if not numbers:
        print("[!] No valid numbers found. Exiting.")
        sys.exit(1)

    print(f"[*] Loaded {len(numbers)} unique phone numbers.")
    print(f"[*] Starting {num_threads} threads ...\n")

    number_queue = queue.Queue()
    for num in numbers:
        number_queue.put(num)

    done_event = threading.Event()

    # ── Graceful Ctrl+C handling on Termux ───────────────────────────────────
    def _sigint(signum, frame):
        print("\n\n[!] Interrupted — stopping threads ...")
        done_event.set()
    try:
        signal.signal(signal.SIGINT, _sigint)
    except Exception:
        pass

    threads = []
    for i in range(1, num_threads + 1):
        t = threading.Thread(
            target=worker,
            args=(i, number_queue, done_event),
            daemon=True,
            name=f"Worker-{i:02d}",
        )
        t.start()
        threads.append(t)

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        done_event.set()
        for t in threads:
            t.join(timeout=5)

    print_stats()
    print(f"[*] Full results saved to: {RESULTS_FILE}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""PC toolkit for the ESP32 ad blocker (standard library only).

Builds a blocklist from named sources (sources.json) by calling tools/build_blocklist.py,
checks that it fits the device's LittleFS, uploads it together with blocklist.json, and
installs firmware over Wi-Fi when the partition layout has two app slots.

  python tools/update.py                        interactive menu
  python tools/update.py --dry-run-all          build every preset and report sizes (no upload)
  python tools/update.py --preset ads+adult     build one preset; add --upload to send it to the device
  python tools/update.py --firmware             install .pio/build/esp32dev/firmware.bin over Wi-Fi
"""
import argparse, base64, datetime, getpass, json, os, re, shutil, subprocess, sys, tempfile, time
import urllib.error, urllib.request, uuid

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
BUILD_SCRIPT = os.path.join(REPO, "tools", "build_blocklist.py")
PARTITIONS = os.path.join(REPO, "partitions.csv")
FIRMWARE = os.path.join(REPO, ".pio", "build", "esp32dev", "firmware.bin")
DATA_DIR = os.path.join(REPO, "data")
OUT, CACHE = os.path.join(HERE, "out"), os.path.join(HERE, "out", "cache")
DEPLOYED, BACKUPS = os.path.join(HERE, "deployed"), os.path.join(HERE, "backups")
RESERVE = 64 * 1024        # LittleFS room kept for settings files (upstream.cfg, allow.txt, ...) + FS overhead
CACHE_HOURS = 6            # re-download a source list when the cached copy is older than this
CSRF = {"X-Requested-With": "c3-adblock"}   # header every state-changing endpoint requires
NO_LIST = ("The device removes its old list before receiving the new one, so it may now have NO blocklist:\n"
           f"  run this again, or upload {os.path.join(DEPLOYED, 'blocklist.bin')} from the dashboard (Lists tab).")

USB_STEPS = """Firmware over USB (first flash of a new layout, or when Wi-Fi updates are not possible):
  1. Plug the ESP32 into this PC (it shows up as a CP210x COM port, e.g. COM5).
  2. Hold the IO0 button (next to the USB port), start the command below, and release IO0
     as soon as "Writing at ..." appears:
     python -m esptool --chip esp32 --port COM5 --baud 460800 --connect-attempts 200 write-flash -z 0x10000 .pio/build/esp32dev/firmware.bin
  A full flash with a new partition table is described in docs/SETUP.md."""


# ---------- sources and device layout ----------
def load_sources():
    with open(os.path.join(HERE, "sources.json"), encoding="utf-8") as f:
        cfg = json.load(f)
    return {s["id"]: s for s in cfg["lists"]}, cfg["presets"]


def partition_info():
    """(LittleFS bytes, largest app slot bytes, has OTA slots) read from partitions.csv."""
    fs = slot = 0
    ota = False
    with open(PARTITIONS, encoding="utf-8") as f:
        for line in f:
            p = [x.strip() for x in line.split("#", 1)[0].split(",")]
            if len(p) < 5 or not p[0]:
                continue
            size = int(p[4], 0)
            if p[2] == "spiffs":
                fs = size
            if p[1] == "app":
                slot, ota = max(slot, size), ota or p[2].startswith("ota_")
    return fs, slot, ota


def budget():
    return partition_info()[0] - RESERVE


# ---------- building ----------
def fetch(src):
    """Local path for a source: its file in this folder, or a cached download of its URL."""
    if "file" in src:
        path = os.path.join(HERE, src["file"])
        return path if os.path.exists(path) else None
    os.makedirs(CACHE, exist_ok=True)
    path = os.path.join(CACHE, src["id"] + ".txt")
    if not os.path.exists(path) or time.time() - os.path.getmtime(path) > CACHE_HOURS * 3600:
        print(f"  downloading {src['name']} ...")
        with urllib.request.urlopen(src["url"], timeout=180) as r, open(path + ".part", "wb") as f:
            shutil.copyfileobj(r, f)
        os.replace(path + ".part", path)
    return path


def entries(path):
    with open(path, encoding="utf-8-sig", errors="ignore") as f:   # -sig: PowerShell 5.1's Out-File adds a BOM
        return [l.split("#", 1)[0].strip() for l in f if l.split("#", 1)[0].strip()]


def build(ids, sources, preset, out_dir):
    """Build blocklist.bin + blocklist.json in out_dir from source ids; returns the metadata."""
    os.makedirs(out_dir, exist_ok=True)
    paths, used, tmp = [], [], None
    for i in ids:
        s = sources[i]
        p = fetch(s)
        if not p or ("file" in s and not entries(p)):
            continue                       # missing or empty local file
        if s["category"] == "allow":       # plain domains -> @@||domain^ rules for build_blocklist.py
            tmp = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
            tmp.writelines(f"@@||{d}^\n" for d in entries(p))
            tmp.close()
            p = tmp.name
        paths.append(p)
        used.append(s)
    if not any(s["category"] != "allow" for s in used):
        raise SystemExit("No block lists selected.")
    out_bin = os.path.join(out_dir, "blocklist.bin")
    r = subprocess.run([sys.executable, BUILD_SCRIPT, out_bin] + paths, capture_output=True, text=True)
    if tmp:
        os.unlink(tmp.name)
    if r.returncode:
        raise SystemExit("build_blocklist.py failed:\n" + r.stdout + r.stderr)
    text = r.stdout + r.stderr

    def num(key):
        m = re.search(key + r"\s*:\s*([\d,]+)", text)
        return int(m.group(1).replace(",", "")) if m else 0

    meta = {"built": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "preset": preset, "domains": num("hash entries"), "bytes": os.path.getsize(out_bin),
            "collisions": num("collisions"), "allowlisted": num("allowlisted"), "skipped_rules": num("skipped rules"),
            "sources": [dict({"id": s["id"], "name": s["name"]}, **({"url": s["url"]} if "url" in s else {"file": s["file"]}))
                        for s in used]}
    with open(os.path.join(out_dir, "blocklist.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=1)
    return meta


def report(meta):
    b = budget()
    size = meta["bytes"]
    fit = f"fits ({size * 100 // b}% of the {b:,}-byte budget)" if size <= b else f"does NOT fit (budget {b:,} bytes)"
    print(f"  {meta['domains']:,} domains, {size:,} bytes ({size / 1048576:.2f} MB), collisions {meta['collisions']} -> {fit}")
    return size <= b


def dry_run_all(sources, presets):
    fs, slot, ota = partition_info()
    print(f"LittleFS {fs:,} bytes - {RESERVE:,} reserve = budget {budget():,} bytes "
          f"({'two app slots, Wi-Fi firmware updates' if ota else 'single app slot, USB firmware updates'})")
    local = [i for i, s in sources.items() if "file" in s and s["enabled"]]
    for name, ids in presets.items():
        print(f"\n[{name}] {', '.join(ids)}")
        report(build(ids + local, sources, name, os.path.join(OUT, "dry-run", name)))


# ---------- device ----------
def request(host, path, auth=None, data=None, ctype=None, timeout=60):
    req = urllib.request.Request(f"http://{host}{path}", data=data, method="POST" if data is not None else "GET")
    for k, v in CSRF.items():
        req.add_header(k, v)
    if auth:
        req.add_header("Authorization", "Basic " + base64.b64encode(auth.encode()).decode())
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def multipart(path):
    b = uuid.uuid4().hex
    head = (f'--{b}\r\nContent-Disposition: form-data; name="f"; filename="{os.path.basename(path)}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n").encode()
    with open(path, "rb") as f:
        return head + f.read() + f"\r\n--{b}--\r\n".encode(), f"multipart/form-data; boundary={b}"


def stats(host):
    try:
        s, t = request(host, "/stats.json", timeout=10)
        return json.loads(t) if s == 200 else None
    except (OSError, ValueError):              # ValueError: invalid JSON (older firmware, a control character in a list)
        return None


def credentials():
    """Asked every time; never stored or printed."""
    user = input("Dashboard user [admin]: ").strip() or "admin"
    return f"{user}:{getpass.getpass('Dashboard password (WEB_PASS, not saved): ')}"


def backup(host):
    """Save the last list this tool deployed plus the device's current metadata and stats."""
    d = os.path.join(BACKUPS, datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))
    os.makedirs(d)
    for f in ("blocklist.bin", "blocklist.json"):
        if os.path.exists(os.path.join(DEPLOYED, f)):
            shutil.copy2(os.path.join(DEPLOYED, f), d)
    for path, name in (("/blocklist.json", "device-blocklist.json"), ("/stats.json", "device-stats.json")):
        s, t = request(host, path, timeout=10)
        if s == 200:
            with open(os.path.join(d, name), "w", encoding="utf-8") as f:
                f.write(t)
    print(f"  backup saved: {d}")


def upload(host, out_dir=OUT):
    meta_path, bin_path = os.path.join(out_dir, "blocklist.json"), os.path.join(out_dir, "blocklist.bin")
    if not os.path.exists(bin_path):
        raise SystemExit("Nothing built yet: build a list first.")
    with open(meta_path, encoding="utf-8") as f:
        meta = json.load(f)
    if not report(meta):
        raise SystemExit("Not uploading: the list does not fit the device.")
    if not stats(host):
        raise SystemExit(f"Device not reachable at http://{host}/")
    auth = credentials()
    backup(host)
    print(f"  uploading blocklist.bin ({meta['bytes']:,} bytes); blocking pauses until it finishes ...")
    try:
        s, t = request(host, "/upload", auth, *multipart(bin_path), timeout=300)
    except OSError as e:
        raise SystemExit(f"Upload failed: {e}\n{NO_LIST}")
    if s == 401:
        raise SystemExit("Wrong user or password (nothing was changed).")
    if s != 200:
        raise SystemExit(f"Upload failed: HTTP {s} {t}\n{NO_LIST}")
    s, t = request(host, "/uploadmeta", auth, *multipart(meta_path))
    print("  blocklist.json: " + ("ok" if s == 200 else f"failed (HTTP {s} {t})"))
    now = stats(host)
    got = now["domains"] if now else None
    ok = got == meta["domains"]
    print(f"  device reports {got if got is None else format(got, ',')} domains, expected {meta['domains']:,} -> "
          + ("OK" if ok else "MISMATCH"))
    if ok:
        os.makedirs(DEPLOYED, exist_ok=True)
        shutil.copy2(bin_path, DEPLOYED)
        shutil.copy2(meta_path, DEPLOYED)


def firmware(host, path=FIRMWARE):
    fs, slot, ota = partition_info()
    s = stats(host)
    if not ota or (s and not s.get("ota")):
        print("This layout has no OTA slot" + (" on the device" if ota else "") + ".\n" + USB_STEPS)
        return
    if not s:
        raise SystemExit(f"Device not reachable at http://{host}/")
    with open(path, "rb") as f:
        data = f.read()
    if data[:1] != b"\xe9":
        raise SystemExit(f"{path} is not an ESP32 firmware image.")
    if len(data) > s["otaMax"]:
        raise SystemExit(f"Firmware is {len(data):,} bytes; the slot holds {s['otaMax']:,}.")
    print(f"Installing {path} ({len(data):,} bytes, slot {s['otaMax']:,}). DNS stops for about 20 seconds.")
    if input("Continue? [y/N] ").strip().lower() != "y":
        return
    auth = credentials()
    try:
        st, t = request(host, "/update", auth, *multipart(path), timeout=300)
    except OSError as e:                       # the device may drop the connection while restarting
        st, t = 0, str(e)
    if st == 401:
        raise SystemExit("Wrong user or password (nothing was changed).")
    if st not in (0, 200):
        raise SystemExit(f"Firmware update failed: HTTP {st} {t}")
    print("  uploaded; waiting for the device to restart ...")
    time.sleep(15)
    for _ in range(12):
        now = stats(host)
        if now:
            print(f"  back online: build {now.get('build')}, uptime {now['uptime']}, {now['domains']:,} domains, "
                  f"free RAM {now['heap']:,} bytes")
            if now.get("build") == s.get("build"):     # a dropped connection also looks like success above
                print("  note: same build as before; fine if you re-installed it, otherwise the update did not take")
            return
        time.sleep(5)
    print("  device not back after 75 s: check its power and Wi-Fi (see SETUP.md).")


def to_data(out_dir=OUT):
    """Copy the build into ../data so `pio run -t buildfs` packs it into a USB filesystem image."""
    for f in ("blocklist.bin", "blocklist.json"):
        shutil.copy2(os.path.join(out_dir, f), DATA_DIR)
    print(f"  copied blocklist.bin + blocklist.json to {DATA_DIR}")


# ---------- menu ----------
def menu(host):
    sources, presets = load_sources()
    ids = list(sources)
    sel = {i for i in ids if sources[i]["enabled"]}
    preset = "custom"
    fs, slot, ota = partition_info()
    while True:
        print(f"\n=== ESP32 ad blocker toolkit ===   device: {host}   list budget: {budget():,} bytes   "
              f"firmware updates: {'Wi-Fi' if ota else 'USB'}")
        print(f"Lists (preset: {preset}):")
        for n, i in enumerate(ids, 1):
            s = sources[i]
            print(f"  {n} [{'x' if i in sel else ' '}] {s['name']}  ({s['category']})")
        print("Commands: number = tick/untick a list, p = preset, b = build, u = upload last build,\n"
              "          f = firmware update, d = dry-run every preset, q = quit")
        c = input("> ").strip().lower()
        try:
            if c.isdigit() and 1 <= int(c) <= len(ids):
                sel ^= {ids[int(c) - 1]}
                preset = "custom"
            elif c == "p":
                names = list(presets)
                for n, name in enumerate(names, 1):
                    print(f"  {n} {name}: {', '.join(presets[name])}")
                k = input("preset number: ").strip()
                if k.isdigit() and 1 <= int(k) <= len(names):
                    preset = names[int(k) - 1]
                    sel = set(presets[preset]) | {i for i in sel if "file" in sources[i]}
            elif c == "b":
                report(build([i for i in ids if i in sel], sources, preset, OUT))
                print(f"  written: {os.path.join(OUT, 'blocklist.bin')} + blocklist.json")
            elif c == "u":
                upload(host)
            elif c == "f":
                firmware(host)
            elif c == "d":
                dry_run_all(sources, presets)
            elif c == "q":
                return
        except SystemExit as e:                # keep the menu running after an error
            print(f"  ! {e}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="c3adblock.local", help="device address (default c3adblock.local)")
    ap.add_argument("--dry-run-all", action="store_true", help="build every preset and report sizes")
    ap.add_argument("--preset", help="build this preset (plus enabled local files) without the menu")
    ap.add_argument("--upload", action="store_true", help="upload after --preset")
    ap.add_argument("--to-data", action="store_true", help="copy the --preset build into ../data for a USB image")
    ap.add_argument("--firmware", action="store_true", help="install .pio/build/esp32dev/firmware.bin over Wi-Fi")
    a = ap.parse_args()
    sources, presets = load_sources()
    if a.dry_run_all:
        dry_run_all(sources, presets)
    elif a.preset:
        if a.preset not in presets:
            raise SystemExit(f"Unknown preset {a.preset!r}; choose from: {', '.join(presets)}")
        local = [i for i, s in sources.items() if "file" in s and s["enabled"]]
        report(build(presets[a.preset] + local, sources, a.preset, OUT))
        if a.to_data:
            to_data()
        if a.upload:
            upload(a.host)
    elif a.firmware:
        firmware(a.host)
    else:
        menu(a.host)


if __name__ == "__main__":
    main()

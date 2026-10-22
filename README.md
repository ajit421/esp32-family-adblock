# esp32-family-adblock

[![build](https://github.com/ajit421/esp32-family-adblock/actions/workflows/build.yml/badge.svg)](https://github.com/ajit421/esp32-family-adblock/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A Pi-hole-style **DNS blocker for ads, trackers and adult sites** that runs on a cheap **ESP32** board — no
PSRAM, no Raspberry Pi. Point your router's DNS at it and every device on your Wi-Fi is filtered.

> Based on [M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock) (MIT), which introduced the
> hash-in-flash blocklist. This version targets the classic ESP32 and adds a family-safe DNS failover chain,
> asynchronous forwarding, a tabbed dashboard, a PC toolkit and security hardening — see [CHANGELOG.md](CHANGELOG.md).

## How it works

```
phone / laptop ──▶ router ──▶ ESP32 (DNS on port 53)
                               ├─ in your allow exceptions?  ──▶ forward upstream
                               ├─ in your custom blocks?     ──▶ 0.0.0.0
                               ├─ in the flash blocklist?    ──▶ 0.0.0.0   (~180k domains)
                               └─ otherwise ──▶ upstream chain (next server only if one fails):
                                    1. Cloudflare Families      1.1.1.3         (300 ms)
                                    2. Cloudflare Families      1.0.0.3         (250 ms)
                                    3. Cisco OpenDNS FamilyShield 208.67.222.123 (250 ms)
                                    4. AdGuard DNS Family       94.140.14.15    (700 ms)
```

The blocklist is never loaded into RAM. Domains are stored as sorted **5-byte (40-bit) FNV-1a hashes** in flash and
binary-searched with a small RAM index and cache, so ~250k domains fit in 1.3 MB of flash and checking the list
takes 1–5 ms. A name is checked together with its parent domains, so blocking `example.com` also blocks
`ads.example.com`.

Blocked names get `0.0.0.0` (A), `::` (AAAA), an AliasMode `.` record (HTTPS/SVCB) or an empty answer for other
types, with a 60 s TTL. The default upstream servers also block adult sites (Cloudflare Families also enforces Google
SafeSearch), so names that are not on the local list are still covered.

## Features

- **Family-safe upstream chain** — 1–5 DNS servers with their own timeouts; the next one is used only on timeout,
  SERVFAIL, REFUSED or a malformed reply. Dashboard presets; unfiltered or custom servers are flagged in red, and
  saving is refused if no server answers a test lookup.
- **Asynchronous forwarding** — up to 16 lookups in flight and a 24-entry receive queue, so one slow server does not
  stall the whole house.
- **Dashboard** at `http://c3adblock.local` — Overview, DNS, Lists, Devices and System tabs: live per-filter and
  per-server stats, recent failures, a domain tester, custom blocks and allow exceptions, pause, per-device ban,
  blocklist upload and firmware update.
- **Over-the-air updates** — two OTA app slots with automatic rollback if a new firmware does not come up healthy.
- **PC toolkit** ([`tools/update.py`](tools/README.md), Python standard library only) — build lists from presets, add
  your own block/allow files, check they fit, back up, upload and verify.
- **Hardened web API** — login + CSRF header on every change, login lockout, Host-header check against DNS rebinding,
  anti-framing headers.
- **Wi-Fi setup portal** — no Wi-Fi details needed at build time.

## Hardware

- A classic **ESP32** dev board with **4 MB flash** (tested: an ESP32-D0WD-V3 board with a CP2102 USB chip). No PSRAM.
- A stable 5 V supply — a phone charger or the router's USB port. Weak supplies cause brown-out resets.
- Optional: a printable case for the ESP32-C3 SuperMini from the original project,
  [`hardware/esp32-c3-supermini-enclosure.stl`](hardware/esp32-c3-supermini-enclosure.stl).

> The `c3` environment is still in `platformio.ini`, but the firmware is currently ~23 KB too large for the C3's
> OTA slot. Use `esp32dev`.

## Quick start

You need [PlatformIO Core](https://docs.platformio.org/en/latest/core/installation/index.html) (or the PlatformIO
VS Code extension) and Python 3.

```bash
git clone https://github.com/ajit421/esp32-family-adblock.git
cd esp32-family-adblock

# 1. Secrets (git-ignored). Wi-Fi is optional (setup portal); the passwords are not.
cp src/secrets.example.h src/secrets.h        # then set WEB_PASS and OTA_PASS (and Wi-Fi if you like)

# 2. Build a blocklist into data/ (ads + trackers + adult, ~180k domains)
python tools/update.py --preset ads+adult --to-data

# 3. First flash over USB: firmware, then the filesystem with the blocklist
pio run -e esp32dev -t upload
pio run -e esp32dev -t uploadfs

# 4. Watch it boot, then open the dashboard
pio device monitor                            # -> http://c3adblock.local
```

If the upload cannot connect, hold the board's **BOOT / IO0** button until `Writing at…` appears. A single esptool
command that writes everything (bootloader, partition table, firmware, filesystem) is in
[docs/SETUP.md §8](docs/SETUP.md#8-usb-flashing-only-for-emergencies).

**Wi-Fi setup:** if the ESP32 cannot join a network (or `secrets.h` has no Wi-Fi details), it opens an open access
point **`C3-AdBlock-XXXX`** with a captive portal. Join it from a phone, pick your **2.4 GHz** network and type the
password. With saved Wi-Fi details it keeps retrying for about 5 minutes first (e.g. after a power cut).

## Put it in front of your network

1. Give the ESP32 a fixed IP with a DHCP reservation in your router, e.g. `192.168.1.10`.
2. Make that IP the only DNS server your network uses — either the DNS your router hands out, or the router's own
   upstream DNS. Leave the second DNS server empty, otherwise devices skip the blocker. To undo, set it back.
3. Test it:
   ```bash
   nslookup doubleclick.net 192.168.1.10    # -> 0.0.0.0
   nslookup github.com 192.168.1.10         # -> a real address
   ```

Browser "secure DNS" (DoH), Android Private DNS and IPv6 DNS handed out by the router all bypass a DNS blocker.
[docs/SETUP.md](docs/SETUP.md) walks through a real install: router settings, the dashboard, a routine and
troubleshooting.

## Updating

| What | How |
|---|---|
| Blocklist (monthly) | `python tools/update.py --preset ads+adult --upload` — downloads fresh lists, builds, checks the size, backs up, uploads and verifies. Or upload `blocklist.bin` + `blocklist.json` on the dashboard's **Lists** tab. |
| Firmware | `pio run -e esp32dev`, then dashboard **System → Firmware update** with `.pio/build/esp32dev/firmware.bin`, or `python tools/update.py --firmware`. |

All DNS lookups stop for the ~10–15 s an upload takes. A new firmware stays *pending* until it has answered a lookup
(or run for 10 minutes); if it restarts before that, the ESP32 boots the previous firmware again.

### Blocklist presets (`tools/sources.json`)

| Preset | Lists | Size (Oct 2026) |
|---|---|---|
| `repo-default` | StevenBlack base + Hagezi Light | ~116k domains, 0.55 MB |
| `ads+adult` | StevenBlack porn (includes base) + Hagezi Light | ~180k, 0.86 MB |
| `adguard-only` | AdGuard DNS filter | ~190k, 0.91 MB |
| `max` | all of the above + Hagezi Pro | ~428k, 2.04 MB — **does not fit** |

The budget is the 1.31 MB LittleFS partition minus 64 KB for settings, about 250k domains. Put your own domains in
`tools/my-block.txt` / `tools/my-allow.txt`. Details: [tools/README.md](tools/README.md).

## Security

Read-only pages (`/`, `/stats.json`, `/blocklist.json`) are open on the LAN. Everything that changes state needs
**HTTP Basic Auth** (`WEB_USER` / `WEB_PASS` from `secrets.h`) **and** the header `X-Requested-With: c3-adblock`,
which a cross-site `<img>` or `<form>` cannot send. Five wrong passwords lock that client out for 60 s, requests with
an unexpected `Host` header get HTTP 421 (DNS-rebinding protection), and the dashboard cannot be framed.
Network OTA (ArduinoOTA) needs `OTA_PASS`.

This protects against other devices on your LAN, not against someone who can sniff it: the dashboard is plain HTTP
and Basic Auth is only base64. Never expose it to the internet, and replace the placeholder passwords from
`secrets.example.h` (the dashboard shows a warning while they are in use).

## Limitations

- DNS blocking only: ads served from the same domains as the content (e.g. YouTube or Instagram in-app ads) cannot
  be blocked this way.
- No DNS over TCP; forwarded lookups ask for answers of at most 1232 bytes, so this rarely matters.
- One list in storage: an upload replaces it, and DNS pauses while it is written.
- Lookups arriving less than ~5 ms apart are partly dropped in the Wi-Fi driver (8 RX buffers in the prebuilt
  Arduino framework). Normal home traffic is far below this.
- 40-bit hashes can collide: about 0 false blocks at 180k domains, about 1 at 500k.

## Project layout

```
src/main.cpp               firmware: DNS, web server, OTA (single loop)
src/page.h                 dashboard HTML/JS, served from flash
src/secrets.example.h      copy to src/secrets.h (git-ignored) and fill in
partitions.csv             2 × 1.31 MB OTA app slots + 1.31 MB LittleFS
platformio.ini             build environments (esp32dev is the default)
tools/update.py            PC toolkit: presets, size check, upload, firmware over Wi-Fi
tools/build_blocklist.py   hosts / domain / AdGuard lists -> sorted 40-bit hash table
tools/sources.json         list catalog and presets
docs/SETUP.md              user guide: router setup, dashboard, routine, troubleshooting
data/                      files packed into the LittleFS image (generated, git-ignored)
hardware/                  3D-printable case (ESP32-C3 SuperMini)
```

## Development

```bash
pio run -e esp32dev                                       # build the firmware
python -m unittest discover -s tools -p "test_*.py" -v    # blocklist tool tests (run from the repo root)
```

After a firmware change, check that `.pio/build/esp32dev/firmware.bin` is at most 1,376,256 bytes (the CI does this
too): PlatformIO's "Flash: x%" figure has been wrong before. The platform is pinned to `espressif32 @ 8.0.0` because
a newer core can silently grow the firmware past the slot.

## Credits

- [M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock) — the original firmware and the
  hash-in-flash design this project is built on.
- [s60sc/ESP32_AdBlocker](https://github.com/s60sc/ESP32_AdBlocker) — the "answer 0.0.0.0 for listed domains" idea
  that inspired the original.
- Blocklists from [StevenBlack/hosts](https://github.com/StevenBlack/hosts),
  [hagezi/dns-blocklists](https://github.com/hagezi/dns-blocklists) and
  [AdGuard](https://github.com/AdguardTeam/HostlistsRegistry). They are downloaded when you build a list, under their
  own licenses, and are not included in this repository.

## License

MIT — see [LICENSE](LICENSE). The original project's copyright notice is kept.

# Changelog

Changes compared with the original project,
[M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock).

## Unreleased

### Added
- DNS tab **Recent**: the last 10 names of every filter (local blocklist, custom blocks, exceptions, banned devices
  and each upstream server's failures) with time, client, matched rule and a repeat count; served by `/recent.json`.
  It replaces the single "Recent failures" list.

### Changed
- DNS traffic uses raw lwIP UDP: each datagram is copied into a ring buffer the moment it arrives, instead of
  waiting in a 6-datagram socket queue that the loop emptied with a 1.5 KB allocation per poll. Bursts of 16 or 32
  lookups are now answered in full (before: ~6 of 16, ~13 of 32).
- The loop no longer sleeps 1 ms per pass (the web server's idle delay) and wakes as soon as a datagram arrives;
  ArduinoOTA is polled 10 times a second.
- The blocklist result cache holds 1024 entries in 4 KB (was 256 in three arrays).
- Custom blocks and exceptions share one list type; unused fields and duplicate code removed. The firmware is
  3.5 KB smaller and uses 8 KB less static RAM.
- The dashboard stops polling while its browser tab is hidden.

### Fixed
- A router re-sending a lookup that is still in flight is no longer counted again in Live stats.

## 1.0.0 — 2026-10-22

### Added
- Upstream DNS chain of 1–5 servers with per-server timeouts (50–1500 ms); the next server is used only on timeout,
  SERVFAIL, REFUSED or a malformed reply. Dashboard presets, a red warning for unfiltered or custom servers, and a
  test lookup on Save that refuses a chain where no server answers.
- Family-filtering defaults: Cloudflare Families → Cisco OpenDNS FamilyShield → AdGuard DNS Family.
- Asynchronous forwarding: up to 16 lookups in flight, a 24-entry receive queue, 4 upstream sockets with periodic
  source-port rotation; a good late answer from an earlier server is accepted, and router repeats of a lookup that
  is still in flight are dropped.
- Tabbed dashboard (Overview, DNS, Lists, Devices, System) with a local-blocklist on/off switch, live per-filter and
  per-server stats and a list of recent upstream failures.
- PC toolkit `tools/update.py`: list catalog and presets, your own block/allow files, size check against the
  LittleFS budget, backup before upload, upload with verification, firmware install over Wi-Fi, `--to-data` for USB
  images.
- Firmware rollback: a new image stays pending until it answers a lookup, accepts an authenticated update or has run
  for 10 minutes; a restart before that boots the previous image.
- HTTPS/SVCB lookups for blocked names get an AliasMode `.` answer (RFC 9460) instead of an empty one, so routers do
  not retry them against an unfiltered resolver.

### Changed
- Default board is the classic ESP32 (`esp32dev`), with a two-slot OTA layout (2 × 1.31 MB app + 1.31 MB LittleFS).
- The on-device remote blocklist download (and TLS) was removed to make two OTA slots fit; lists are built and
  uploaded from the PC.
- Blocked answers use a 60 s TTL (was 300 s), so Pause and new exceptions take effect quickly.
- Forwarded lookups cap the EDNS UDP size at 1232 bytes.
- The PlatformIO platform is pinned to `espressif32 @ 8.0.0`.
- The blocklist tools read files as UTF-8 with or without a byte-order mark.
- The PC scripts live together in `tools/`.

### Security
- Five wrong passwords lock a client out for 60 s (HTTP 429), without slowing down DNS.
- Host-header check (HTTP 421) against DNS rebinding; `X-Frame-Options: DENY` and a `frame-ancestors 'none'` policy
  on the dashboard.
- Uploads without a valid login are cut off immediately, so a slow fake upload cannot stall DNS.
- Malformed DNS questions get FORMERR at once instead of being forwarded; DNS responses (QR = 1) are dropped.
- Domain names are validated when added and when loaded, and control characters are escaped in JSON.
- `/ban` refuses the gateway and the device's own IP (banning the router would cut off the whole network).

### Fixed
- Names with more than 32 labels now get the parent-domain check.
- Bans are kept for devices not seen since the last restart.
- Uptime no longer wraps after 49.7 days.
- The router's MAC address is looked up again when it first shows as all zeros.

### Removed
- The ESP32-C3 web installer (`docs/` firmware images), the Japanese README and the weekly blocklist release
  workflow; this firmware no longer downloads lists itself.

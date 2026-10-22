# tools — PC side

Python 3, standard library only — no `pip install` needed. Run the commands from the repo root.

| File | What it is |
|---|---|
| `update.py` | The toolkit: builds blocklists from presets, checks they fit the ESP32, uploads them and installs firmware over Wi-Fi |
| `build_blocklist.py` | Turns hosts / plain-domain / AdGuard lists into the sorted 40-bit hash table the firmware searches (`update.py` calls it) |
| `test_build_blocklist.py` | Unit tests for `build_blocklist.py` |
| `sources.json` | The list catalog (id, name, URL, category, enabled) and the presets |
| `my-block.txt` | Your own blocked domains, one per line (also blocks subdomains) |
| `my-allow.txt` | Domains to remove from the build (exact entries only — use the dashboard's exceptions to also allow subdomains) |
| `out/` | Last build: `blocklist.bin` + `blocklist.json`; `out/cache/` holds downloaded lists (re-downloaded after 6 hours) |
| `deployed/` | Copy of the last list that was uploaded and verified |
| `backups/<date-time>/` | Made before every upload: the previous deployed list + the device's `blocklist.json` and stats |

`out/`, `deployed/` and `backups/` are git-ignored.

## update.py

```powershell
python tools\update.py                                  # menu
python tools\update.py --dry-run-all                    # build every preset, show sizes (uploads nothing)
python tools\update.py --preset ads+adult --upload      # build and upload
python tools\update.py --preset ads+adult --to-data     # build and copy into data\ for a USB filesystem image
python tools\update.py --firmware                       # install .pio\build\esp32dev\firmware.bin over Wi-Fi
```

Add `--host 192.168.1.10` if `c3adblock.local` does not resolve.

### Presets

| Preset | Lists | Size (Oct 2026) |
|---|---|---|
| `repo-default` | StevenBlack base + Hagezi Light | ~116k domains, 0.55 MB |
| `ads+adult` | StevenBlack porn (includes base) + Hagezi Light | ~180k, 0.86 MB |
| `adguard-only` | AdGuard DNS filter | ~190k, 0.91 MB |
| `max` | everything | ~428k, 2.04 MB — does **not** fit the two-slot layout |

The budget is the LittleFS partition in `partitions.csv` minus 64 KB kept for settings files. A list that
does not fit is never uploaded.

### How it works

- Building calls `tools/build_blocklist.py` (the hashing lives there only); `my-allow.txt` is turned into
  `@@||domain^` rules for it.
- Upload: asks for the dashboard user and password every time (`getpass`, never saved or printed), backs up,
  POSTs `/upload` then `/uploadmeta` with the `X-Requested-With: c3-adblock` header, then checks the device's
  domain count. All DNS stops for the few seconds the upload takes.
- Firmware: only offered when `partitions.csv` and the device both have OTA slots; checks the file is an ESP32
  image (first byte `0xE9`) and fits the slot. Otherwise it prints the USB steps.

## build_blocklist.py

```bash
python tools/build_blocklist.py OUT.bin [SOURCE ...]     # no SOURCE = StevenBlack base + Hagezi Light
```

Sources are URLs or local files, in any mix of these formats:

- **hosts files** — `0.0.0.0 ads.example.com tracker.example.com` (every domain on the line is included)
- **plain domain lists** — one domain per line
- **AdGuard / Adblock basic rules** — `||ads.example.com^` blocks, `@@||ok.example.com^` removes that exact entry

A blocked domain also blocks its subdomains. Rules a DNS hash list cannot express (regex, wildcards, `$`
modifiers, cosmetic `##` rules) are skipped and counted. If a source cannot be downloaded the build stops instead
of silently producing a smaller list (`--allow-missing` to override). `HASH_BYTES` must match `src/main.cpp`.

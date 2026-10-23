# SETUP — your ESP32 ad blocker

Day-to-day guide for running the blocker: an ESP32 board that blocks ads, trackers and adult sites for
every device on your home Wi-Fi.

> The examples come from a real install: an Airtel ZTE F670L router at `192.168.1.1` and the ESP32 at
> `192.168.1.10`. Use your own router's menus and addresses. Commands are PowerShell, run from the repo folder.

- Dashboard: **http://c3adblock.local** (if that does not open: **http://192.168.1.10**)
- Login (only needed to change things): `WEB_USER` (default **admin**) and `WEB_PASS` from `src/secrets.h`

---

## 1. How it works (one minute)

```
phone / laptop  ->  Airtel router (192.168.1.1)  ->  ESP32 (192.168.1.10)
                                                     |- on the blocklist?  -> answers 0.0.0.0 (blocked)
                                                     '- not on the list    -> asks the DNS servers in order:
                                                        1. Cloudflare Families 1.1.1.3   (blocks adult sites, Google SafeSearch)
                                                        2. Cloudflare Families 1.0.0.3   (only if 1 fails)
                                                        3. Cisco FamilyShield 208.67.222.123 (only if 1 and 2 fail)
                                                        4. AdGuard Family 94.140.14.15   (only if 1-3 fail)
```

Many lookups are handled at the same time (up to 16 waiting for an answer), so one slow server no longer
makes the others wait.

- The **blocklist** (179,839 ads, trackers and adult domains) lives on the ESP32 and answers in ~20 ms.
- Your router sends every device's lookups to the ESP32, so you do not need to change anything on phones or laptops.

---

## 2. Where to keep the ESP32

| Do | Why |
|---|---|
| Power it from a **phone charger** (5 V, 1 A or more) or the **router's USB port** | If it is powered from the PC, it turns off when the PC sleeps or shuts down |
| Keep it **on all the time** | When it is off, lookups slow down or fail until the router gives up on it |
| Put it **near the router** | The dashboard's Wi-Fi value should be better than **−70 dBm** (−50 is great, −80 is bad) |
| Leave space around it | It normally runs at 50–65 °C; that is fine |
| Do not press the buttons | IO0 / EN are only for USB flashing (section 8) |

The ESP32 uses your **2.4 GHz** Wi-Fi (it has no 5 GHz radio). If you rename the Wi-Fi or change its password, see section 9.

---

## 3. Your routine

**Every day:** nothing. It runs by itself.

**Once a week (1 minute, optional):** open the dashboard and check:
- top right says **Blocking active** (not Paused)
- **Failovers / SERVFAIL** stays low. A few failovers are normal; **SERVFAIL** should stay near 0
- **Free RAM** is above ~100 KB

**Once a month (5 minutes):** update the blocklist so new ad domains are blocked (section 6).

**When a site or app breaks:** test the domain and add an exception (section 5, Lists tab).

---

## 4. Router settings (Airtel ZTE F670L, http://192.168.1.1)

These are already done. Keep this for reference and for undoing.

| Setting | Where | Value |
|---|---|---|
| Fixed IP for the ESP32 | Local Network → LAN → IPv4 → **DHCP Binding** | `adblock`, the ESP32's MAC → `192.168.1.10` |
| Send all lookups to the ESP32 | Local Network → **DNS** → DNS → **IPv4 DNS Server1** | `192.168.1.10` (Server2 stays `0.0.0.0`) |
| IPv6 off on the home network | Local Network → LAN → **IPv6** tab → **RA Service** | **Off** (since 2026-10-22) |

**Undo (if the internet stops working and the ESP32 is the cause):** set **IPv4 DNS Server1** back to
`0.0.0.0` → **Apply**. The house goes back to Airtel's DNS (no blocking) until you fix the ESP32.

**Why IPv6 is off:** the router answers IPv6 lookups itself from Airtel, without asking the ESP32. With IPv6 on,
devices got normal Google (no SafeSearch) and some ads over IPv6. With RA Service **Off**, devices use IPv4 only,
and every lookup goes through the ESP32. To turn IPv6 back on: set RA Service to **On** → **Apply** (the
blocking then has that gap again). Everything works over IPv4; most homes never notice.

---

## 5. Using the dashboard

The bar at the top shows **Blocking active** and a **Pause** button (pause for 30 s / 5 min / 30 min / until
you resume) — useful when a site misbehaves and you want to check if the blocker is the reason.

### Overview
Numbers at a glance: blocked / allowed lookups, blocklist size, Wi-Fi signal, temperature, free RAM, uptime,
failovers, storage. Below: which DNS servers are in use and which blocklist is loaded.

### DNS
- **Filters** (top box) shows the order every lookup goes through:
  1. **Local blocklist** (179,839 domains) — with an **On/Off** switch. Off = names on the list are no longer
     blocked by the ESP32 (the family DNS servers still block adult sites, but most ads get through). A red
     warning shows while it is off; the setting is saved on the device.
  2. **Your custom blocks and exceptions** (Lists tab) — always on.
  3. **DNS servers** — up to **5**, used in order; the next one only when the previous one fails.
- **Presets:** one click fills the form, then press **Save**.
  - **Recommended chain** — Cloudflare 1.1.1.3 (300 ms) → Cloudflare 1.0.0.3 (250) → Cisco FamilyShield (250) →
    AdGuard (700): the chain tuned on your network, also the firmware's default
  - **Max safety (5 servers)** — Cloudflare 1.1.1.3 → 1.0.0.3 → Cisco OpenDNS FamilyShield 208.67.222.123 →
    208.67.220.123 → AdGuard. Same speed as Recommended normally (server 1 answers); more backups if servers fail.
  - **Cloudflare only** — the two Cloudflare servers
  - **Cisco FamilyShield** — Cisco OpenDNS FamilyShield (blocks adult sites, fast from your network, but no SafeSearch)
  - **AdGuard only** — also forces YouTube Restricted Mode, but is slower from your network
  - **Local list only** — blocking comes only from the ESP32's own list (179,839 domains); everything else
    goes to plain, fast Cloudflare 1.1.1.1 → 1.0.0.1. Adult sites that are *not* on the list, and Google
    SafeSearch, are **not** covered (red warning). Use it if the family servers block something you need.
  - **Quad9** — *no adult filter* (the page shows a red warning)
- **Save checks the servers first:** the ESP32 sends a test lookup to each server. If **none** answers, it
  does **not** save ("not saved: no server answered…"), so you can't lock the house out of the internet by
  mistake. If only some don't answer, it saves and tells you which ones.
- **Mode:** *Chain* (2–5 servers, the next is used only when one fails) or *Single* (one server; if it does
  not answer, the lookup fails — not recommended).
- **Server list:** Cloudflare Families, AdGuard Family and Cisco OpenDNS FamilyShield (all block adult
  sites), plus Cloudflare 1.1.1.1/1.0.0.1, Cisco OpenDNS Home and Quad9 (no adult filter — red warning).
- **Custom IP…:** pick it in any row and type any DNS server's IP. Custom servers count as **unfiltered**
  (red warning) because the ESP32 cannot know whether they block adult sites.
- **Timeout:** how long to wait before moving to the next server (50–1500 ms). Keep **250 ms** for Cloudflare
  and **700 ms** for AdGuard. Long timeouts make everything slow when a server is down.
- **Live stats:** one table in the same order as the Filters box:
  - **1 Local blocklist** — how many lookups it checked, how many it blocked (and %), and how long checking
    the list takes (normally 1–5 ms).
  - **2 Custom blocks / Exceptions** — how many your own rules blocked or let through, and their check time
    (a few hundredths of a millisecond).
  - Local filters never fail and never wait on the internet, so *Failures* is always 0 and *Timeout* says
    "none (local)".
  - **3.1–3.5 DNS servers** — answers, failures and speed per server ("—" until a server has answered at least once).
  - Red means something was blocked or failed; zero is never shown in red.
  - Below: *Answered locally* (blocked on the ESP32 without asking any server), failovers and SERVFAILs.
  Local numbers count since the last restart; server numbers since the last Save or restart.
- **Recent:** the last 10 names of every filter, numbered like Live stats: what the local blocklist and your
  custom blocks blocked (and which parent domain matched), what your exceptions let through, what banned devices
  asked, and each server's failures (timeout, SERVFAIL, REFUSED or a bad reply). Each row shows when, which device
  asked, and *Times*: a name asked again (a page asks for the same name several times) moves to the top and counts
  up instead of filling the list. Look here when a site breaks or when SERVFAIL or failovers go up.

### Lists
- **Test a domain:** type a name (e.g. `doubleclick.net`) → **Test**. It tells you *blocked by the local
  blocklist*, *blocked by your custom list*, *allowed by your exception*, or which DNS server answered and what
  it answered (including *blocked by the upstream filter*).
- **Loaded blocklist:** number of domains, build date and the source lists.
- **Upload a new blocklist:** `blocklist.bin` (+ `blocklist.json` for the details). Easier with the PC toolkit (section 6).
- **Custom blocked domains:** block one more domain (and its subdomains). Max 200.
- **Allowed exceptions:** unblock a domain that the list blocks by mistake (and its subdomains), e.g. a
  shopping link like `app.link`. Max 200. The upstream filter (Cloudflare) still applies.

### Devices
Every device that asked the ESP32 directly. Because the router forwards for everyone, most traffic shows as
one client: `192.168.1.1`. **Ban** blocks *all* lookups from a device (it asks first). The router row has no
Ban button: banning it would block every device.

### System
- **Firmware update:** choose `firmware.bin` → **Install firmware** (section 7).
- **Device:** IP, uptime, **last start** (why it last restarted — "brownout" means a weak power supply),
  free RAM, temperature, storage.
- **Forget WiFi:** see section 9.

---

## 6. Updating the blocklist (PC, monthly)

In PowerShell:

```powershell
cd esp32-family-adblock
python tools\update.py --preset ads+adult --upload
```

It downloads the latest lists, builds them, checks the size, asks for the dashboard password (it is never
saved), makes a backup in `tools\backups\`, uploads, and checks the new domain count.
All DNS lookups stop for ~10–15 s during the upload. The ESP32 removes the old list first, so if an upload
fails, run it again (or upload `tools\deployed\blocklist.bin` on the Lists tab).

- **Menu** (pick lists one by one, add your own files): run `tools\update.py` with no options.
- **Your own domains:** put them in `tools\my-block.txt` (blocked) or `my-allow.txt` (removed from the list).
- **Sizes:** the ESP32 holds up to **1.31 MB** (~250,000 domains). `ads+adult` uses 0.86 MB. `max` does not fit.
- Details: `tools\README.md`.

---

## 7. Updating the firmware (over Wi-Fi, no USB)

1. Build it (only after a code change):
   ```powershell
   python -m platformio run -e esp32dev        # the Python that has PlatformIO (e.g. a venv); or: pio run -e esp32dev
   ```
2. Dashboard → **System** → **Firmware update** → choose
   `.pio\build\esp32dev\firmware.bin` (in the repo folder) → **Install firmware**.
   (Or: `python tools\update.py --firmware`.)
3. The page reloads after ~20 s. **System → last start** should say *software restart*, and
   **firmware built** shows the new build time. Other dashboard tabs that were open reload themselves too.

The new firmware goes into the spare slot and is checked before the switch, so a damaged upload is refused.
After the restart it counts as *not confirmed* until it has answered its first DNS lookup (normally within a
second). If it crashes or restarts before that, the ESP32 goes back to the previous firmware by itself. Your
blocklist and settings are kept. Before installing, copy the old `firmware.bin` into
a backup folder outside the repo so you can go back.

---

## 8. USB flashing (only for emergencies)

Needed only if the ESP32 no longer starts or joins Wi-Fi, or to change the partition layout.

1. Plug the ESP32 into the PC (it appears as a COM port, e.g. **COM5** for a Silicon Labs CP210x).
2. **Hold the IO0 button** (top button, next to the USB port), start the command, and **release IO0 when
   "Writing at…" appears**. Some boards (including the one this guide was written on) need the button; they do not enter flashing mode by themselves.
   (Tip: a 10 µF capacitor between EN and GND usually fixes that.)
3. Firmware only:
   ```powershell
   python -m esptool --chip esp32 --port COM5 --baud 460800 --connect-attempts 200 write-flash -z 0x10000 .pio\build\esp32dev\firmware.bin
   ```
4. Everything (firmware + partition table + blocklist + DNS settings) — first build the files
   (`$py` = the Python that has PlatformIO installed; `esptool` can be in any Python):
   ```powershell
   cd esp32-family-adblock
   $py = "python"     # or the python.exe of the venv where PlatformIO is installed
   & $py tools\update.py --preset ads+adult --to-data     # puts the list into data\
   & $py -m platformio run -e esp32dev                                # firmware, bootloader, partitions
   & $py -m platformio run -e esp32dev -t buildfs                     # filesystem image from data\
   ```
   `data\upstream.cfg` (one `<ip> <timeout_ms>` line per DNS server) is packed too, if it exists.
   then (one command, hold IO0 as above):
   ```powershell
   $b = ".pio\build\esp32dev"; python -m esptool --chip esp32 --port COM5 --baud 460800 --connect-attempts 200 write-flash -z 0x1000 $b\bootloader.bin 0x8000 $b\partitions.bin 0xe000 $env:USERPROFILE\.platformio\packages\framework-arduinoespressif32\tools\partitions\boot_app0.bin 0x10000 $b\firmware.bin 0x2b0000 $b\littlefs.bin
   ```
   A full flash replaces the custom lists and exceptions with what is in `data\` — write them down first.

---

## 9. Troubleshooting

| Problem | What to do |
|---|---|
| **Internet is down for everyone** | Is the ESP32 powered and is the dashboard reachable? If not, power-cycle it (unplug 5 s). Still down: router → DNS Server1 → `0.0.0.0` (section 4) |
| **Dashboard does not open** | Try http://192.168.1.10. Check the ESP32 has power. Wait 1 minute after a restart. "wrong host name" means you used another name: use `c3adblock.local` or the IP |
| **"too many wrong passwords"** | 5 wrong passwords lock your device out for 60 seconds. Wait a minute and log in again |
| **A site or app does not work** | Lists → Test a domain. If it says *blocked*, add an exception. Quick check: Pause blocking for 5 min |
| **Ads still show** | YouTube, Instagram and Hotstar in-app ads come from the same servers as the videos — DNS cannot block them. In Chrome/Edge turn off **Settings → Privacy → Use secure DNS**; on Android turn off **Private DNS**; otherwise those devices skip the blocker. Also check that RA Service is still **Off** on the router (section 4) |
| **SERVFAIL keeps rising** | A DNS server is down or slow. Check the DNS tab stats; use the Recommended chain (300 / 250 / 250 / 700 ms) and check *Recent failures* on the DNS tab |
| **Everything is slow** | Same as above; also check the Wi-Fi signal (better than −70 dBm). Don't set Cloudflare timeouts below 250 ms: new names often need 230–300 ms, and shorter timeouts push them to slower backups |
| **A mistyped address takes ~4 s to show an error** | Normal with this router: it re-asks "name does not exist" answers several times. The ESP32 answers in ~0.3 s; real websites are not affected |
| **ESP32 keeps restarting** | System → *last start*: **brownout** = power supply too weak (use a better charger or cable); **crash** = note the time and the firmware version |
| **You changed the Wi-Fi name or password** | The ESP32 cannot join, waits 30 s, then opens its own open Wi-Fi **C3-AdBlock-XXXX**. Join it with your phone **within 3 minutes** (otherwise it restarts and tries again), pick the new network, type the password. Then also update `WIFI_SSID` / `WIFI_PASS` in `secrets.h` for the next firmware build |
| **"Forget WiFi" did nothing** | Expected when `secrets.h` has Wi-Fi details: it only clears a network picked in the setup portal, so the ESP32 reconnects with the details from `secrets.h` |
| **Forgot the dashboard password** | It is `WEB_PASS` in `src/secrets.h` on the PC |
| **Upload says "too big"** | Choose a smaller preset (section 6) |

---

## 10. Passwords and safety

- `src/secrets.h` holds the Wi-Fi password, `WEB_PASS` (dashboard) and `OTA_PASS`. It is **git-ignored** —
  never share it or paste it anywhere.
- To change the dashboard password: edit `WEB_PASS` in `secrets.h` → build (section 7, step 1) → install the
  firmware from the dashboard (log in with the **old** password one last time).
- The dashboard is plain HTTP inside your home network. Do not open it to the internet.

---

## 11. Backups

Keep undo copies **outside the repo** (`*.bin` files are not committed):

| What | Why |
|---|---|
| The `blocklist.bin` you are running (e.g. ads + adult, ~180k) | Re-upload it on the Lists tab if a new list causes trouble |
| An ads-only list (~116k, preset `repo-default`) | Fallback if the adult list blocks something you need |
| Earlier `firmware.bin` files | Install one from the dashboard to go back |
| `tools\backups\` | Made automatically before each toolkit upload (git-ignored) |
| `tools\deployed\blocklist.bin` | The last list the toolkit uploaded and verified (git-ignored) |

---

## 12. Technical reference

- Board used: ESP32-D0WD-V3 (classic ESP32), 4 MB flash, CP2102 USB chip.
- Flash layout (`partitions.csv`): two 1.31 MB app slots (Wi-Fi updates) + 1.31 MB LittleFS for the blocklist and settings.
- Settings files on the ESP32: `/upstream.cfg` (DNS servers: `<ip> <timeout_ms>` per line, up to 5),
  `/filter.cfg` (`list on` / `list off`),
  `/custom.txt`, `/allow.txt`, `/banned.txt`, `/blocklist.bin`, `/blocklist.json`.
  Uploading a new blocklist only replaces `/blocklist.bin` and `/blocklist.json`.
- Dashboard endpoints that change things need the login **and** the header `X-Requested-With: c3-adblock`:
  `/setupstream`, `/setlist`, `/addblock`, `/unblock`, `/addallow`, `/unallow`, `/test`, `/ban`, `/pause`, `/resume`,
  `/upload`, `/uploadmeta`, `/update`, `/forgetwifi`, plus `/auth` (only checks the login; the page calls it before
  uploads, because the ESP32 cuts off uploads without a valid login). Read-only: `/`, `/stats.json`, `/recent.json`,
  `/blocklist.json`.
- 5 wrong passwords from one device lock it out for 60 s (HTTP 429). Requests for a host name other than
  `c3adblock.local`, `c3adblock`, the IP or a `.local`/`.lan`/`.home` name get HTTP 421 (protection against DNS rebinding).

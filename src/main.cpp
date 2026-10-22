// C3 AdBlock — DNS sinkhole + web dashboard for the ESP32 (classic ESP32 by default; no PSRAM needed).
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched.
// Dashboard at http://c3adblock.local : per-client stats, system info,
// ban clients, add custom block domains. All control state persisted to flash.

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>            // firmware OTA
// No HTTPClient/WiFiClientSecure: the remote blocklist auto-fetch was dropped (lists are built and
// uploaded from the PC, see tools/update.py); TLS cost ~150 KB, which two OTA slots need.
#include <ArduinoOTA.h>        // network firmware flashing (pio run over wifi)
#include <DNSServer.h>         // captive-portal catch-all DNS
#include <Preferences.h>       // NVS store for provisioned WiFi creds
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "esp_ota_ops.h"       // is there an OTA slot? (dashboard hides the firmware upload if not)
#include "esp_timer.h"         // 64-bit uptime: millis() wraps after 49.7 days
#include "secrets.h"   // WIFI_SSID / WIFI_PASS — used only as a FALLBACK if no creds
                       // have been provisioned via the captive portal (copy secrets.example.h)

// ---- config ----
#ifndef UPSTREAM_PORT
#define UPSTREAM_PORT 53
#endif
// Upstreams, tried in order; the next is used ONLY if the previous fails (timeout, SERVFAIL/REFUSED,
// malformed/oversized reply). All fail -> SERVFAIL. Set from the dashboard (/setupstream) and kept in
// /upstream.cfg as one "<ip> <timeout_ms>" line per server (1 line = single mode, 2-5 = chain).
struct Upstream { IPAddress ip; uint16_t timeoutMs; uint32_t ok, fail, sumMs, maxMs; };
static const int MAX_UPSTREAMS = 5;
static const long UP_TIMEOUT_MIN = 50, UP_TIMEOUT_MAX = 1500;
// The chain tuned on this network: Cloudflare's first lookup of a name often takes 230-300 ms, so 300 ms first.
static const char* DEFAULT_UPSTREAMS = "1.1.1.3:300,1.0.0.3:250,208.67.222.123:250,94.140.14.15:700";
// Known resolvers. Anything not listed is shown as "Custom" and treated as unfiltered.
struct KnownDns { uint8_t ip[4]; const char* name; bool filtered; };
static const KnownDns KNOWN_DNS[] = {
  {{1, 1, 1, 3},      "Cloudflare Families",    true},
  {{1, 0, 0, 3},      "Cloudflare Families #2", true},
  {{94, 140, 14, 15}, "AdGuard Family",         true},
  {{94, 140, 15, 16}, "AdGuard Family #2",      true},
  {{208, 67, 222, 123}, "Cisco OpenDNS FamilyShield",    true},
  {{208, 67, 220, 123}, "Cisco OpenDNS FamilyShield #2", true},
  {{1, 1, 1, 1},      "Cloudflare (no filter)",    false},   // "Local list only" preset
  {{1, 0, 0, 1},      "Cloudflare #2 (no filter)", false},
  {{208, 67, 222, 222}, "Cisco OpenDNS Home",    false},
  {{208, 67, 220, 220}, "Cisco OpenDNS Home #2", false},
  {{9, 9, 9, 9},      "Quad9",                  false},
};
// Changes with every build; the dashboard reloads itself when it sees a different one, so a tab left
// open across a firmware update can't keep running (and saving from) the old page.
static const char* BUILD_ID = __DATE__ " " __TIME__;
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
static const int INDEX_ENTRIES = 4096;   // 20 KB first-level flash index
static const int CACHE_SIZE = 256;       // must be power of 2
static const int MAX_RANGE = 256;        // max hashes per index bucket (fine up to ~1M hashes; flash holds far fewer)

// ---- globals ----
WiFiUDP dnsServer, probeCli;            // probeCli: only the blocking lookups of /test and the /setupstream probe
WebServer web(80);
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0, totalFailovers = 0, totalServfail = 0;
// Local filter stats since restart (dashboard LIVE STATS): lookups checked, and what each local filter did.
uint32_t locChecked = 0, locList = 0, locCustom = 0, locAllow = 0, locBan = 0;
// Time each local filter takes per lookup (microseconds), filled by classify().
struct StageTime {
  uint64_t sum = 0; uint32_t max = 0, n = 0;
  void add(uint32_t us) { sum += us; n++; if (us > max) max = us; }
  uint32_t avg() const { return n ? (uint32_t)(sum / n) : 0; }
};
StageTime tAllow, tCustom, tList;
uint8_t buf[1536];   // fits any non-fragmented UDP reply (EDNS answers can exceed 512)
static uint8_t qsave[sizeof(buf)];   // the client's query, kept so it can be resent to the next upstream
Upstream ups[MAX_UPSTREAMS]; int numUps = 0;
static uint32_t upSecs() { return (uint32_t)(esp_timer_get_time() / 1000000ULL); }

// first-level flash index (sorted sample hashes) + small direct-mapped cache
static uint8_t blIndex[INDEX_ENTRIES][HASH_BYTES];
static uint8_t cacheKey[CACHE_SIZE][HASH_BYTES];
static uint8_t cacheRes[CACHE_SIZE];
static uint8_t cacheValid[CACHE_SIZE];
static uint8_t rangeBuf[MAX_RANGE * HASH_BYTES];

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; String label; };
static const int MAX_CLIENTS = 96;
Dev clients[MAX_CLIENTS]; int numClients = 0;

static const int MAX_CUSTOM = 200;
String customDom[MAX_CUSTOM]; uint64_t customHash[MAX_CUSTOM]; int numCustom = 0;
// Allow list: exceptions for false positives. Checked before custom blocks and the blocklist.
static const int MAX_ALLOW = 200;
String allowDom[MAX_ALLOW]; uint64_t allowHash[MAX_ALLOW]; int numAllow = 0;
// The local blocklist can be switched off as a filter (DNS tab); saved in /filter.cfg. Custom blocks,
// exceptions and bans keep working either way.
bool listOn = true;

static const int MAX_BAN = 32;
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;

// WiFi provisioning (captive portal)
Preferences prefs;
DNSServer   dnsPortal;
String      portalOpts;             // <option> list of scanned networks, built once at portal start

// blocking pause (Pi-hole-style "disable for a while")
bool     blockingOn = true;
uint32_t resumeAt   = 0;            // millis() to auto-resume; 0 = paused indefinitely / not paused

// OTA rollback. The core marks a new firmware valid before setup() even runs, so an update that crashed at start
// kept rebooting until it was reflashed over USB with IO0 held. Now it stays "pending" until it has answered a
// lookup through an upstream (or run 10 min); if it restarts before that, the bootloader boots the old one.
extern "C" bool verifyRollbackLater() { return true; }
static bool fwPending = false;
static void markFirmwareGood(const char* why) {
  if (!fwPending) return;
  fwPending = false; esp_ota_mark_app_valid_cancel_rollback(); Serial.printf("[fw-ota] new firmware confirmed (%s)\n", why);
}
// For /stats.json: "valid" after an update means the bootloader supports rollback and the confirm step ran;
// "new" would mean the bootloader ignores it (then nothing rolls back).
static const char* otaState() {
  esp_ota_img_states_t st; if (esp_ota_get_state_partition(esp_ota_get_running_partition(), &st) != ESP_OK) return "none";
  switch (st) { case ESP_OTA_IMG_NEW: return "new"; case ESP_OTA_IMG_PENDING_VERIFY: return "pending"; case ESP_OTA_IMG_VALID: return "valid";
    case ESP_OTA_IMG_INVALID: return "invalid"; case ESP_OTA_IMG_ABORTED: return "aborted"; default: return "undefined"; }
}

// ---------- hashing / matching ----------
static uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}
static inline uint64_t unpackHash(const uint8_t* b) {
  uint64_t v = 0;
  for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
  return v;
}
static inline void packHash(uint64_t h, uint8_t* b) {
  for (int k = 0; k < HASH_BYTES; k++) { b[k] = (uint8_t)h; h >>= 8; }
}

static void buildFlashIndex() {
  if (!blocklist || numHashes == 0) return;
  for (int i = 0; i < INDEX_ENTRIES; i++) {
    uint32_t pos = (uint32_t)((uint64_t)i * (numHashes - 1) / (INDEX_ENTRIES - 1));
    blocklist.seek((uint32_t)pos * HASH_BYTES);
    blocklist.read(blIndex[i], HASH_BYTES);
  }
  for (int i = 0; i < CACHE_SIZE; i++) cacheValid[i] = 0;
}

static bool inFlash(uint64_t h) {
  if (numHashes == 0) return false;
  uint64_t first = unpackHash(blIndex[0]);
  uint64_t last  = unpackHash(blIndex[INDEX_ENTRIES - 1]);
  if (h < first || h > last) return false;

  int lo = 0, hi = INDEX_ENTRIES - 2, seg = 0;
  while (lo <= hi) {
    int mid = (lo + hi) >> 1;
    uint64_t midv = unpackHash(blIndex[mid]);
    if (midv < h) {
      seg = mid;
      lo = mid + 1;
    } else if (midv > h) {
      hi = mid - 1;
    } else {
      return true;
    }
  }

  uint32_t startPos = (uint32_t)((uint64_t)seg * (numHashes - 1) / (INDEX_ENTRIES - 1));
  uint32_t endPos   = (uint32_t)((uint64_t)(seg + 1) * (numHashes - 1) / (INDEX_ENTRIES - 1));
  if (endPos >= numHashes) endPos = numHashes - 1;
  uint32_t rangeCount = endPos - startPos + 1;
  if (rangeCount > (uint32_t)MAX_RANGE) rangeCount = MAX_RANGE;

  blocklist.seek((uint32_t)startPos * HASH_BYTES);
  blocklist.read(rangeBuf, (uint32_t)rangeCount * HASH_BYTES);

  for (uint32_t i = 0; i < rangeCount; i++) {
    uint64_t v = unpackHash(rangeBuf + i * HASH_BYTES);
    if (v == h) return true;
    if (v > h) break;
  }
  return false;
}

static bool inHashes(const uint64_t* hs, int n, uint64_t h) { for (int i = 0; i < n; i++) if (hs[i] == h) return true; return false; }

// Only flash results are cached: the flash list only changes via reopenBlocklist(), which
// rebuilds the index and clears the cache. Custom and allow domains change at runtime, so
// they're checked uncached (a short linear scan) to avoid serving stale answers.
static bool inFlashCached(uint64_t h) {
  if (numHashes == 0) return false;                 // no list, or mid-swap: don't trust the cache
  uint32_t slot = h & (CACHE_SIZE - 1);
  if (cacheValid[slot]) {
    uint8_t want[HASH_BYTES]; packHash(h, want);
    bool same = true;
    for (int k = 0; k < HASH_BYTES; k++) if (cacheKey[slot][k] != want[k]) { same = false; break; }
    if (same) return cacheRes[slot] != 0;
  }
  bool res = inFlash(h);
  cacheValid[slot] = 1;
  cacheRes[slot] = res ? 1 : 0;
  packHash(h, cacheKey[slot]);
  return res;
}

// Why a name is (not) blocked. Each rule matches the name itself or any parent domain;
// an allow entry wins over custom blocks and the blocklist.
enum Verdict : uint8_t { V_PASS, V_ALLOW, V_CUSTOM, V_LIST };
static Verdict classify(const char* domain, const char** hit) {
  const char* ps[32]; uint64_t hs[32]; int k = 0, dots = 0;
  for (const char* p = domain; *p; p++) dots += *p == '.';
  // Over 32 levels keep the 32 nearest the TLD: the first 32 used to be kept, so a.a.(40 labels).ads.com passed.
  const char* start = domain; for (int skip = dots - 32; skip > 0; skip--) start = strchr(start, '.') + 1;
  for (const char* p = start; p && *p && k < 32; ) {
    ps[k] = p; hs[k++] = fnv40(p, strlen(p));
    const char* dot = strchr(p, '.'); if (!dot) break;
    const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
  }
  uint32_t t = micros();
  for (int i = 0; i < k; i++) if (inHashes(allowHash, numAllow, hs[i])) { tAllow.add(micros() - t); *hit = ps[i]; return V_ALLOW; }
  tAllow.add(micros() - t);
  Verdict v = V_PASS; uint32_t usCustom = 0, usList = 0;
  for (int i = 0; i < k && v == V_PASS; i++) {
    t = micros(); const bool c = inHashes(customHash, numCustom, hs[i]); usCustom += micros() - t;
    if (c) { *hit = ps[i]; v = V_CUSTOM; break; }
    if (!listOn) continue;
    t = micros(); const bool l = inFlashCached(hs[i]); usList += micros() - t;
    if (l) { *hit = ps[i]; v = V_LIST; }
  }
  tCustom.add(usCustom); if (listOn && v != V_CUSTOM) tList.add(usList);
  return v;
}

// ---------- persistence ----------
// Custom block list (/custom.txt) and allow list (/allow.txt): one domain per line.
// Only plain names are kept (letters, digits, . - _, the same rule as /test): a pasted hosts line
// ("0.0.0.0<TAB>ads.x.com") or a line break used to be stored as-is, broke /stats.json, and after a restart
// split into a different name.
static const char* NOT_ADDED = "not added: enter a domain like ads.example.com (letters, digits, . - _ only), not already listed, max 200";
static bool cleanDomain(String& d) {
  d.trim(); d.toLowerCase(); if (d.endsWith(".")) d.remove(d.length() - 1); if (d.startsWith("www.")) d = d.substring(4);
  if (d.length() < 3 || d.length() > 253 || d.indexOf('.') <= 0 || d.endsWith(".") || d.indexOf("..") >= 0) return false;
  for (char ch : d) if (!isalnum((unsigned char)ch) && ch != '.' && ch != '-' && ch != '_') return false;
  return true;
}
static void loadList(const char* path, String* dom, uint64_t* hash, int& n, int max) {
  n = 0; File f = LittleFS.open(path, "r"); if (!f) return;
  while (f.available() && n < max) {
    String l = f.readStringUntil('\n');
    if (cleanDomain(l)) { dom[n] = l; hash[n] = fnv40(l.c_str(), l.length()); n++; }   // bad lines from older firmware are dropped
  }
  f.close();
}
static void saveList(const char* path, const String* dom, int n) { File f = LittleFS.open(path, "w"); if (!f) return; for (int i = 0; i < n; i++) f.println(dom[i]); f.close(); }
static bool addToList(String d, const char* path, String* dom, uint64_t* hash, int& n, int max) {
  if (!cleanDomain(d) || n >= max) return false;
  for (int i = 0; i < n; i++) if (dom[i] == d) return false;
  dom[n] = d; hash[n] = fnv40(d.c_str(), d.length()); n++; saveList(path, dom, n); return true;
}
static void removeFromList(String d, const char* path, String* dom, uint64_t* hash, int& n) {
  d.toLowerCase();
  for (int i = 0; i < n; i++) if (dom[i] == d) {
    for (int j = i; j < n - 1; j++) { dom[j] = dom[j+1]; hash[j] = hash[j+1]; }
    n--; saveList(path, dom, n); return;
  }
}
static void loadCustom() { loadList("/custom.txt", customDom, customHash, numCustom, MAX_CUSTOM); }
static bool addCustom(String d) { return addToList(d, "/custom.txt", customDom, customHash, numCustom, MAX_CUSTOM); }
static void removeCustom(String d) { removeFromList(d, "/custom.txt", customDom, customHash, numCustom); }
static void loadFilterCfg() {
  File f = LittleFS.open("/filter.cfg", "r"); if (!f) return;
  String l = f.readStringUntil('\n'); l.trim(); listOn = l != "list off"; f.close();
}
static void saveFilterCfg() { File f = LittleFS.open("/filter.cfg", "w"); if (!f) return; f.println(listOn ? "list on" : "list off"); f.close(); }
static void loadAllow() { loadList("/allow.txt", allowDom, allowHash, numAllow, MAX_ALLOW); }
static bool addAllow(String d) { return addToList(d, "/allow.txt", allowDom, allowHash, numAllow, MAX_ALLOW); }
static void removeAllow(String d) { removeFromList(d, "/allow.txt", allowDom, allowHash, numAllow); }
static bool isBannedIP(uint32_t ip) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true; return false; }
static void loadBanned() {
  numBanned = 0; File f = LittleFS.open("/banned.txt", "r"); if (!f) return;
  while (f.available() && numBanned < MAX_BAN) { String l = f.readStringUntil('\n'); l.trim(); IPAddress ip; if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip; }
  f.close();
}
// bannedIP[] is the ban list; clients[].banned only mirrors it for the Devices tab. (It used to be rebuilt from
// the client table, which dropped bans for devices not seen since the last restart.)
static void saveBanned() {
  File f = LittleFS.open("/banned.txt", "w"); if (!f) return;
  for (int i = 0; i < numBanned; i++) { IPAddress ip(bannedIP[i]); f.println(ip.toString()); }
  f.close();
}
static const KnownDns* knownDns(const IPAddress& ip) {
  for (const KnownDns& k : KNOWN_DNS) if (ip == IPAddress(k.ip[0], k.ip[1], k.ip[2], k.ip[3])) return &k;
  return nullptr;
}
static const char* upName(const IPAddress& ip) { const KnownDns* k = knownDns(ip); return k ? k->name : "Custom"; }
static bool upFiltered(const IPAddress& ip) { const KnownDns* k = knownDns(ip); return k && k->filtered; }
// Parse 1-5 servers: "ip:ms,ip:ms" (dashboard) or one "ip ms" per line (/upstream.cfg).
// Rejects this device and the gateway as upstreams: the router forwards to us, so either would loop.
static bool parseUpstreams(String spec, Upstream* out, int& n, String& err) {
  spec.replace('\r', ','); spec.replace('\n', ','); spec.replace(' ', ':');
  n = 0; int start = 0;
  while (start < (int)spec.length()) {
    int end = spec.indexOf(',', start); if (end < 0) end = spec.length();
    String item = spec.substring(start, end); item.trim(); start = end + 1;
    if (!item.length()) continue;
    if (n >= MAX_UPSTREAMS) { err = "at most " + String(MAX_UPSTREAMS) + " servers"; return false; }
    int c = item.indexOf(':'); IPAddress ip;
    if (c < 0 || !ip.fromString(item.substring(0, c)) || ip[0] == 0 || ip[0] == 127 || ip[0] >= 224) { err = "bad server: " + item; return false; }
    if (ip == WiFi.localIP() || ip == WiFi.gatewayIP()) { err = "would loop back through the router: " + item; return false; }
    long ms = item.substring(c + 1).toInt();
    if (ms < UP_TIMEOUT_MIN || ms > UP_TIMEOUT_MAX) { err = "timeout must be 50-1500 ms: " + item; return false; }
    out[n++] = Upstream{ip, (uint16_t)ms, 0, 0, 0, 0};
  }
  if (!n) { err = "no servers"; return false; }
  return true;
}
static void loadUpstreams() {
  String spec, err; File f = LittleFS.open("/upstream.cfg", "r");
  if (f) { spec = f.readString(); f.close(); }
  if (spec.length() && parseUpstreams(spec, ups, numUps, err)) return;
  if (spec.length()) Serial.printf("[upstream] bad /upstream.cfg (%s) -> default chain\n", err.c_str());
  parseUpstreams(DEFAULT_UPSTREAMS, ups, numUps, err);
}
static void saveUpstreams() {
  File f = LittleFS.open("/upstream.cfg", "w"); if (!f) return;
  for (int i = 0; i < numUps; i++) f.printf("%s %u\n", ups[i].ip.toString().c_str(), ups[i].timeoutMs);
  f.close();
}

// ---------- client table ----------
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6); ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) {
    Dev& c = clients[i]; c.lastSeen = millis();
    if (!(c.mac[0] | c.mac[1] | c.mac[2] | c.mac[3] | c.mac[4] | c.mac[5])) getMac(ip, c.mac);   // not in the ARP table at first sight
    return &c;
  }
  if (numClients < MAX_CLIENTS) {
    Dev* c = &clients[numClients++];
    c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis(); c->banned = isBannedIP(ip); c->label = "";
    getMac(ip, c->mac); return c;
  }
  return nullptr;
}

// ---------- DNS ----------
// Name length (0 for the root), or -1 if the question is malformed (cut off, compressed, over 254 characters).
static int parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return -1; int i = 12, o = 0;
  while (i < len) { uint8_t l = pkt[i++]; if (l == 0) break; if (l & 0xC0) return -1;
    if (o + l + 1 > 254 || i + l > len) return -1; if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]); }
  out[o] = 0; if (i + 4 > len) return -1; *qtype = (pkt[i] << 8) | pkt[i + 1]; *qend = i + 4;
  if (o > 4 && strncmp(out, "www.", 4) == 0) { memmove(out, out + 4, o - 3); o -= 4; }
  return o;
}
// A -> 0.0.0.0, AAAA -> ::. An empty (NODATA) AAAA reply makes some ISP routers' DNS relays
// (seen on a ZTE F670L) retry and then fall back to their own upstream, leaking the real IPv6 address.
// TTL 60 s (was 300): the router caches the answer, so Pause or a new exception took up to 5 min to reach devices.
// HTTPS/SVCB (65/64) get an AliasMode record with target "." (RFC 9460: service not available) instead of NODATA:
// the router retried the empty answer for ~1 s per blocked name, and a retry could reach the ISP's unfiltered DNS.
static int buildBlocked(int qend, uint16_t qtype) {
  const bool a = qtype == 1, aaaa = qtype == 28, svc = qtype == 64 || qtype == 65;
  buf[2] = 0x81; buf[3] = 0x80; buf[6] = 0; buf[7] = (a || aaaa || svc) ? 1 : 0; buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  if (svc) { const uint8_t ans[] = {0xC0,0x0C, 0,(uint8_t)qtype, 0,1, 0,0,0,60, 0,3, 0,0, 0}; memcpy(buf + qend, ans, sizeof(ans)); return qend + sizeof(ans); }
  if (!a && !aaaa) return qend;
  const uint8_t rdlen = a ? 4 : 16;
  const uint8_t ans[] = {0xC0,0x0C, 0,(uint8_t)qtype, 0,1, 0,0,0,60, 0,rdlen};
  memcpy(buf + qend, ans, sizeof(ans)); memset(buf + qend + sizeof(ans), 0, rdlen);
  return qend + sizeof(ans) + rdlen;
}
// Ask ONE upstream and wait for the reply that actually belongs to THIS query. Only /test and the /setupstream
// probe still wait like this (on probeCli); normal lookups go through the pending table further down.
// Issue #10: after one timeout the late reply used to sit in the socket and get relayed
// to the next client (every answer shifted by one). Now: drain stale datagrams first,
// send with a fresh random txid, and only accept a reply whose txid, question section,
// and source address/port match. Returns the reply length in buf, or 0 on failure (*why set).
// NXDOMAIN and empty answers are valid replies; only SERVFAIL/REFUSED count as failures.
static int askUpstream(Upstream& u, int qlen, int ql, const char** why) {
  probeCli.clear();                                      // release any half-read buffer
  while (probeCli.parsePacket() > 0) probeCli.clear();   // drop stale late replies
  const uint16_t wid = (uint16_t)esp_random();
  memcpy(buf, qsave, qlen); buf[0] = wid >> 8; buf[1] = wid & 0xFF;
  probeCli.beginPacket(u.ip, UPSTREAM_PORT); probeCli.write(buf, qlen); probeCli.endPacket();
  const uint32_t t0 = millis();
  *why = "timeout";
  while (millis() - t0 < u.timeoutMs) {                  // deadline, not a retry count
    int sz = probeCli.parsePacket();
    if (sz <= 0) { delay(1); continue; }
    const bool fromUp = probeCli.remoteIP() == u.ip && probeCli.remotePort() == UPSTREAM_PORT;
    int n = probeCli.read(buf, sizeof(buf));
    probeCli.clear();
    if (!fromUp || n < 2 || buf[0] != (wid >> 8) || buf[1] != (wid & 0xFF)) continue;   // not ours: keep waiting
    if (n < 12 || !(buf[2] & 0x80) || (ql && (n < 12 + ql || memcmp(buf + 12, qsave + 12, ql) != 0))) { *why = "malformed"; break; }
    const uint8_t rcode = buf[3] & 0x0F;
    if (rcode == 2 || rcode == 5) { *why = rcode == 2 ? "SERVFAIL" : "REFUSED"; break; }
    const uint32_t ms = millis() - t0; u.ok++; u.sumMs += ms; if (ms > u.maxMs) u.maxMs = ms;
    return n;
  }
  u.fail++; return 0;
}
// Every upstream failed: answer SERVFAIL (question echoed, no records) instead of staying silent.
static int buildServfail(int qlen, int ql) {
  const int len = 12 + ql;
  memcpy(buf, qsave, len);
  buf[2] = 0x81; buf[3] = 0x82; if (!ql) { buf[4] = 0; buf[5] = 0; } buf[6] = 0; buf[7] = 0; buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  return len;
}
// The last few upstream failures, for the DNS tab: otherwise the reason only reaches the serial log.
struct Fail { uint32_t at; IPAddress ip; char why[10]; char name[48]; };
static const int MAX_FAILS = 10;
static Fail fails[MAX_FAILS]; static int numFails = 0, failNext = 0;
static void noteFail(const IPAddress& ip, const char* why, const char* name) {
  Fail& f = fails[failNext]; f.at = upSecs(); f.ip = ip; strlcpy(f.why, why, sizeof(f.why)); strlcpy(f.name, name, sizeof(f.name));
  failNext = (failNext + 1) % MAX_FAILS; if (numFails < MAX_FAILS) numFails++;
}
// Blocking forward, for /test and the rare query too big for a pending slot: try each upstream in order, moving on
// only when one fails. The client's txid is restored on the way back; each upstream's own answer (incl. its block
// page) passes through unchanged.
static int lastUp = -1;                                  // which upstream answered the last forward (-1: none)
static int forwardUpstream(int qlen, int qend, const char* domain) {
  memcpy(qsave, buf, qlen);                              // buf gets overwritten by replies
  const int ql = (qend > 12 && qend <= qlen) ? qend - 12 : 0;
  lastUp = -1;
  for (int i = 0; i < numUps; i++) {
    const char* why = "";
    int n = askUpstream(ups[i], qlen, ql, &why);
    if (n > 0) { buf[0] = qsave[0]; buf[1] = qsave[1]; lastUp = i; markFirmwareGood("answered a lookup"); return n; }
    const bool last = i + 1 == numUps;
    if (last) totalServfail++; else totalFailovers++;
    noteFail(ups[i].ip, why, domain);
    Serial.printf("[dns] %s %s for %s -> %s\n", ups[i].ip.toString().c_str(), why, domain, last ? "SERVFAIL" : ups[i + 1].ip.toString().c_str());
  }
  return buildServfail(qlen, ql);
}
// Cap the EDNS UDP size a query advertises at 1232 (the DNS Flag Day value). lwIP hands over at most 1460 bytes of
// a datagram and drops fragmented ones (no IP reassembly), so bigger answers arrived cut off or not at all.
static void capEdns(uint8_t* q, int qlen, int qend) {
  if (q[6] | q[7] | q[8] | q[9] || !(q[10] | q[11]) || qend + 11 > qlen || q[qend] != 0 || q[qend + 1] != 0 || q[qend + 2] != 41) return;
  if (((q[qend + 3] << 8) | q[qend + 4]) > 1232) { q[qend + 3] = 1232 >> 8; q[qend + 4] = 1232 & 0xFF; }
}

// ---------- forwarding without waiting ----------
// Lookups used to be forwarded one at a time: the loop waited for every upstream answer, so a slow or dead server
// made each lookup in the house queue behind the previous one (dead first server: 0.5-0.8 s each), and as lwIP keeps
// only 6 datagrams per socket, 23 of 30 simultaneous lookups were simply lost. Now a forwarded query takes a slot and
// the loop keeps serving; replies and timeouts are handled as they come. A good answer from a server that was
// already given up on is still taken (it used to be thrown away).
static const int MAX_PENDING = 16, MAX_Q = 512, NUM_SOCKS = 4;
struct Pending {
  bool used; IPAddress cip; uint16_t cport, cid, uid, qlen, ql; uint8_t up, sock, tried;   // tried: one bit per upstream asked
  uint32_t sentAt[MAX_UPSTREAMS]; char name[48]; uint8_t q[MAX_Q];
};
static Pending pend[MAX_PENDING];
static WiFiUDP upSock[NUM_SOCKS];                        // 4 sockets = 4 x 6 datagrams of lwIP buffer for replies
static uint32_t rotatedAt = 0;
static void sendTo(Pending& p, int i) {                  // (re)send p's query to upstream i, under p's own txid
  p.up = i; p.tried |= 1 << i; p.sentAt[i] = millis();
  memcpy(buf, p.q, p.qlen); buf[0] = p.uid >> 8; buf[1] = p.uid & 0xFF;
  WiFiUDP& s = upSock[p.sock]; s.beginPacket(ups[i].ip, UPSTREAM_PORT); s.write(buf, p.qlen); s.endPacket();
}
static void answerClient(Pending& p, int n) {            // reply in buf[0..n) -> the client, under its own txid
  buf[0] = p.cid >> 8; buf[1] = p.cid & 0xFF;
  dnsServer.beginPacket(p.cip, p.cport); dnsServer.write(buf, n); dnsServer.endPacket(); p.used = false;
}
static void upstreamFailed(Pending& p, const char* why) {   // the current upstream failed: the next one, or SERVFAIL after the last
  const int i = p.up; const bool last = i + 1 >= numUps;
  ups[i].fail++; if (last) totalServfail++; else totalFailovers++;
  noteFail(ups[i].ip, why, p.name);
  Serial.printf("[dns] %s %s for %s -> %s\n", ups[i].ip.toString().c_str(), why, p.name, last ? "SERVFAIL" : ups[i + 1].ip.toString().c_str());
  if (!last) { sendTo(p, i + 1); return; }
  memcpy(buf, p.q, 12 + p.ql); buf[2] = 0x81; buf[3] = 0x82; if (!p.ql) { buf[4] = 0; buf[5] = 0; } memset(buf + 6, 0, 6);
  answerClient(p, 12 + p.ql);
}
static void forwardAsync(Pending& p, const IPAddress& cip, uint16_t cport, int qlen, int qend, const char* name) {
  p.used = true; p.cip = cip; p.cport = cport; p.cid = (buf[0] << 8) | buf[1]; p.qlen = qlen;
  p.ql = (qend > 12 && qend <= qlen) ? qend - 12 : 0; p.tried = 0; p.sock = (&p - pend) % NUM_SOCKS;
  strlcpy(p.name, name, sizeof(p.name)); memcpy(p.q, buf, qlen);
  for (bool taken = true; taken; ) {                     // a txid no other query on this socket is waiting for
    p.uid = (uint16_t)esp_random(); taken = false;
    for (const Pending& x : pend) if (&x != &p && x.used && x.sock == p.sock && x.uid == p.uid) taken = true;
  }
  sendTo(p, 0);
}
static bool inFlight(const IPAddress& cip, uint16_t cport, uint16_t cid) {   // the router re-sends what it still waits for
  for (const Pending& p : pend) if (p.used && p.cid == cid && p.cport == cport && p.cip == cip) return true;
  return false;
}
// Same checks as askUpstream: txid, source address/port, question echo; SERVFAIL/REFUSED/malformed = failure.
static bool pollUpstreams() {
  bool did = false;
  for (int s = 0; s < NUM_SOCKS; s++) for (int budget = 0; budget < 8; budget++) {
    WiFiUDP& u = upSock[s]; if (u.parsePacket() <= 0) break;
    did = true;
    const IPAddress from = u.remoteIP(); const uint16_t fport = u.remotePort();
    const int n = u.read(buf, sizeof(buf)); u.clear();
    if (n < 12 || fport != UPSTREAM_PORT || !(buf[2] & 0x80)) continue;
    const uint16_t id = (buf[0] << 8) | buf[1];
    Pending* p = nullptr; for (Pending& x : pend) if (x.used && x.sock == s && x.uid == id) { p = &x; break; }
    if (!p) continue;                                    // nobody waits for it (already answered, or stray)
    int i = -1; for (int k = 0; k < numUps; k++) if ((p->tried >> k & 1) && ups[k].ip == from) { i = k; break; }
    if (i < 0) continue;                                 // not from a server this query went to
    const char* bad = n < 12 + p->ql || memcmp(buf + 12, p->q + 12, p->ql) != 0 ? "malformed" : nullptr;
    const uint8_t rc = buf[3] & 0x0F; if (!bad && (rc == 2 || rc == 5)) bad = rc == 2 ? "SERVFAIL" : "REFUSED";
    if (bad) { if (i == p->up) upstreamFailed(*p, bad); continue; }   // a bad late answer from an earlier server changes nothing
    const uint32_t ms = millis() - p->sentAt[i]; Upstream& up = ups[i]; up.ok++; up.sumMs += ms; if (ms > up.maxMs) up.maxMs = ms;
    answerClient(*p, n); markFirmwareGood("answered a lookup");
  }
  return did;
}
static void checkTimeouts() {
  const uint32_t now = millis();
  for (Pending& p : pend) if (p.used && now - p.sentAt[p.up] >= ups[p.up].timeoutMs) upstreamFailed(p, "timeout");
}
// A fresh source port per socket every minute (when nothing waits on it): a spoofed reply can't just aim at one
// port that never changes. The random txid and the question check remain the main defence.
static void rotatePorts() {
  if (millis() - rotatedAt < 60000) return;
  rotatedAt = millis();
  for (int s = 0; s < NUM_SOCKS; s++) {
    bool busy = false; for (const Pending& p : pend) if (p.used && p.sock == s) busy = true;
    if (!busy) { upSock[s].stop(); upSock[s].begin(0); }
  }
}
static void dropPending() { for (Pending& p : pend) p.used = false; }   // the upstream list changed; the router retries
static Pending* freeSlot() { for (Pending& p : pend) if (!p.used) return &p; return nullptr; }

// One client query in buf[0..qlen): answer it here (blocked, malformed) or hand it to a pending slot.
static void processQuery(const IPAddress& cip, uint16_t cport, int qlen, Pending& slot) {
  if (qlen < 13 || (buf[2] & 0x80)) return;             // a response: never answer or forward it
  char domain[256]; uint16_t qtype = 0; int qend = qlen;
  const int dl = parseQuery(buf, qlen, domain, &qtype, &qend);
  if (dl < 0) {                                          // malformed: FORMERR now, instead of trying every upstream (1-1.6 s of stalled DNS each)
    buf[2] = 0x80 | (buf[2] & 0x79); buf[3] = 0x01; memset(buf + 4, 0, 8);
    dnsServer.beginPacket(cip, cport); dnsServer.write(buf, 12); dnsServer.endPacket(); return;
  }
  Dev* c = getClient((uint32_t)cip);
  const bool ban = numBanned && isBannedIP((uint32_t)cip);   // also works when the client table is full
  const char* hit = ""; Verdict v = V_PASS;
  if (ban) locBan++;
  else if (blockingOn && dl) {
    v = classify(domain, &hit); locChecked++;
    if (v == V_LIST) locList++; else if (v == V_CUSTOM) locCustom++; else if (v == V_ALLOW) locAllow++;
  }
  if (ban || v >= V_CUSTOM) {
    const int rlen = buildBlocked(qend, qtype); totalBlocked++; if (c) c->blocked++;
    dnsServer.beginPacket(cip, cport); dnsServer.write(buf, rlen); dnsServer.endPacket(); return;
  }
  if (inFlight(cip, cport, (buf[0] << 8) | buf[1])) return;
  totalAllowed++; if (c) c->allowed++;
  capEdns(buf, qlen, qend);
  if (qlen <= MAX_Q) { forwardAsync(slot, cip, cport, qlen, qend, dl ? domain : "?"); return; }
  const int rlen = forwardUpstream(qlen, qend, dl ? domain : "?");   // a query over 512 bytes: the old blocking way
  dnsServer.beginPacket(cip, cport); dnsServer.write(buf, rlen); dnsServer.endPacket();
}

// A burst is read out of the socket first and worked through afterwards. lwIP keeps only 6 datagrams per socket and
// checking a name against the flash list takes ~2.5 ms (up to 15), so of 30 lookups arriving 2 ms apart 22 were
// dropped while the first ones were being checked; reading one out takes a small fraction of that.
static const int RXQ = 24, RXQ_LEN = 300;
struct RxQuery { IPAddress ip; uint16_t port, len; uint8_t d[RXQ_LEN]; };
static RxQuery rxq[RXQ]; static int rxHead = 0, rxCount = 0;
static bool drainDns() {
  bool did = false;
  while (rxCount < RXQ) {
    const int sz = dnsServer.parsePacket(); if (sz <= 0) break;
    did = true;
    const IPAddress ip = dnsServer.remoteIP(); const uint16_t port = dnsServer.remotePort();
    if (sz > RXQ_LEN) {                                  // rare big query: handle it right away from buf
      const int n = dnsServer.read(buf, sizeof(buf)); dnsServer.clear();
      if (Pending* s = freeSlot()) processQuery(ip, port, n, *s);
      continue;
    }
    RxQuery& r = rxq[(rxHead + rxCount) % RXQ]; r.ip = ip; r.port = port;
    r.len = dnsServer.read(r.d, sizeof(r.d)); dnsServer.clear(); rxCount++;
  }
  return did;
}
// Returns true if anything was handled (the loop only sleeps when nothing was).
static bool handleDns() {
  bool did = pollUpstreams() | drainDns();
  for (int budget = 0; budget < 16 && rxCount; budget++) {
    Pending* slot = freeSlot(); if (!slot) break;        // 16 lookups in flight: the rest wait in the queue
    RxQuery& r = rxq[rxHead]; rxHead = (rxHead + 1) % RXQ; rxCount--;
    memcpy(buf, r.d, r.len); processQuery(r.ip, r.port, r.len, *slot);
    did |= drainDns();                                   // keep the socket empty while names are being checked
  }
  checkTimeouts();
  return did;
}

// ---------- web ----------
static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
// JSON string escaping. Control characters need \u escapes too: a raw tab or line break in a custom domain made
// /stats.json invalid and froze the dashboard.
static String jesc(const String& s) {
  String o; for (char ch : s) { if ((uint8_t)ch < 0x20) { char u[7]; snprintf(u, sizeof(u), "\\u%04x", (uint8_t)ch); o += u; continue; }
    if (ch == '"' || ch == '\\') o += '\\'; o += ch; }
  return o;
}
// HTML text/attribute escaping for the setup portal. jesc() covers JSON (stats
// endpoint); the portal builds HTML, and its inputs — a scanned SSID, the
// submitted WiFi name — are attacker-controllable during provisioning (the
// portal AP is open, and a nearby attacker can also broadcast an SSID of their
// choosing). Without escaping both, a crafted SSID/name is reflected script
// into the setup page, the same class as the dashboard XSS fixed earlier.
static String htmlEscape(const String& s) {
  String o; o.reserve(s.length());
  for (char ch : s) {
    switch (ch) {
      case '&':  o += "&amp;";  break;
      case '<':  o += "&lt;";   break;
      case '>':  o += "&gt;";   break;
      case '"':  o += "&quot;"; break;
      case '\'': o += "&#39;";  break;
      default:   o += ch;
    }
  }
  return o;
}

#include "page.h"   // dashboard HTML (PROGMEM) — see issue #6

// Why the device last started. On the classic ESP32 a reset from the EN pin (button or the USB
// adapter's RTS line) also reports POWERON, so the two can't be told apart.
static const char* resetReason() {
  switch (esp_reset_reason()) {
    case ESP_RST_POWERON:  return "power-on or EN/USB reset";
    case ESP_RST_SW:       return "software restart (update or reboot)";
    case ESP_RST_PANIC:    return "crash (panic)";
    case ESP_RST_INT_WDT: case ESP_RST_TASK_WDT: case ESP_RST_WDT: return "watchdog";
    case ESP_RST_BROWNOUT: return "brownout (power dip)";
    case ESP_RST_EXT:      return "external reset";
    default:               return "other";
  }
}

static void handleStats() {
  const uint32_t up = upSecs();
  char ut[24]; snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  const esp_partition_t* otaPart = esp_ota_get_next_update_partition(NULL);   // null = single-app layout
  String j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"uptime\":\"" + ut + "\",\"reset\":\"" + resetReason() + "\",\"build\":\"" + BUILD_ID + "\"" +
             ",\"blocking\":" + (blockingOn ? "true" : "false") + ",\"listOn\":" + (listOn ? "true" : "false") +
             ",\"failovers\":" + totalFailovers + ",\"servfail\":" + totalServfail +
             ",\"local\":{\"checked\":" + locChecked + ",\"list\":" + locList + ",\"custom\":" + locCustom + ",\"allow\":" + locAllow +
             ",\"ban\":" + locBan + ",\"listUs\":" + tList.avg() + ",\"listMax\":" + tList.max + ",\"customUs\":" + tCustom.avg() +
             ",\"customMax\":" + tCustom.max + ",\"allowUs\":" + tAllow.avg() + ",\"allowMax\":" + tAllow.max + "}" +
             ",\"fsUsed\":" + LittleFS.usedBytes() + ",\"fsTotal\":" + LittleFS.totalBytes() +
             ",\"ota\":" + (otaPart ? "true" : "false") + ",\"otaMax\":" + (otaPart ? otaPart->size : 0) +
             ",\"otaState\":\"" + otaState() + "\",\"gw\":\"" + WiFi.gatewayIP().toString() + "\"" +
             ",\"resumeIn\":" + (uint32_t)(!blockingOn && resumeAt ? (resumeAt - millis()) / 1000 : 0) +
             ",\"defcreds\":" + ((strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0) ? "true" : "false") +
             ",\"clients\":[";
  for (int i = 0; i < numClients; i++) { Dev& c = clients[i]; IPAddress ip(c.ip);
    j += (i ? "," : ""); j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (c.banned?"true":"false") + "}"; }
  j += "],\"bans\":[";                                // also bans of devices not seen since the restart (unban from the page)
  for (int i = 0; i < numBanned; i++) { j += (i ? ",\"" : "\""); j += IPAddress(bannedIP[i]).toString() + "\""; }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
  j += "],\"allow\":[";
  for (int i = 0; i < numAllow; i++) { j += (i ? "," : ""); j += "\"" + jesc(allowDom[i]) + "\""; }
  j += "],\"ups\":[";
  for (int i = 0; i < numUps; i++) { Upstream& u = ups[i];
    j += (i ? "," : ""); j += "{\"ip\":\"" + u.ip.toString() + "\",\"name\":\"" + upName(u.ip) + "\",\"filtered\":" + (upFiltered(u.ip) ? "true" : "false") +
         ",\"to\":" + u.timeoutMs + ",\"ok\":" + u.ok + ",\"fail\":" + u.fail + ",\"avg\":" + (u.ok ? u.sumMs / u.ok : 0) + ",\"max\":" + u.maxMs + "}"; }
  j += "],\"fails\":[";
  for (int k = 0; k < numFails; k++) { const Fail& f = fails[(failNext - 1 - k + MAX_FAILS) % MAX_FAILS];   // newest first
    j += (k ? "," : ""); j += "{\"ago\":" + String(up - f.at) + ",\"up\":\"" + f.ip.toString() + "\",\"why\":\"" + f.why + "\",\"name\":\"" + jesc(f.name) + "\"}"; }
  j += "]}";
  web.send(200, "application/json", j);
}
// Upstream shipped every state-changing/OTA endpoint with zero authentication —
// anyone on the LAN could reflash firmware or rewrite the blocklist. Gate them.
//
// Basic Auth alone isn't enough here: these are GET endpoints with side effects,
// and browsers auto-attach cached Basic Auth credentials to *any* request to an
// already-authenticated origin — including one triggered by a completely
// unrelated page the victim's browser visits later (e.g. <img src="http://
// c3adblock.local/forgetwifi">). That's CSRF, and it defeats the LAN-attacker
// threat model entirely: the attacker doesn't need network access, just to get
// the victim's browser to fire one request. A custom header can't be attached
// by a plain <img>/<form> CSRF vector (only same-origin fetch() can set it, and
// that's exactly what the dashboard's own JS does), so requiring one blocks the
// drive-by case without needing TLS, cookies, or a token endpoint.
static const char* CSRF_HEADER = "X-Requested-With";
static const char* CSRF_VALUE  = "c3-adblock";
// Wrong passwords: 5 from one address lock that address out for 60 s (429). Guessing used to be unlimited
// (15 tries in 2.1 s); a delay() per miss would have frozen DNS for the whole house instead.
struct AuthMiss { uint32_t ip, last, until; uint8_t n; };
static AuthMiss misses[8];
static AuthMiss* findMiss(uint32_t ip, bool add) {
  AuthMiss* old = &misses[0];
  for (AuthMiss& m : misses) { if (m.ip == ip) return &m; if (m.last < old->last) old = &m; }
  if (!add) return nullptr;
  *old = AuthMiss{ip, 0, 0, 0}; return old;
}
static uint32_t lockLeft() {                       // seconds this client is still locked out (0 = not locked)
  const AuthMiss* m = findMiss((uint32_t)web.client().remoteIP(), false);
  return m && m->until && (int32_t)(m->until - millis()) > 0 ? (m->until - millis()) / 1000 + 1 : 0;
}
static bool checkPassword() {
  if (lockLeft()) return false;
  if (web.authenticate(WEB_USER, WEB_PASS)) return true;
  if (web.header("Authorization").length()) {      // a wrong password (a browser's first try sends none)
    AuthMiss* m = findMiss((uint32_t)web.client().remoteIP(), true); m->last = millis();
    if (++m->n >= 5) { m->n = 0; m->until = millis() + 60000; Serial.printf("[auth] 5 wrong passwords from %s: locked 60 s\n", web.client().remoteIP().toString().c_str()); }
  }
  return false;
}
static bool requireAuth() {
  if (web.header(CSRF_HEADER) != CSRF_VALUE) { web.send(403, "text/plain", "missing CSRF header"); return false; }
  if (const uint32_t s = lockLeft()) { web.send(429, "text/plain", "too many wrong passwords: try again in " + String(s) + " s"); return false; }
  if (checkPassword()) return true;
  web.requestAuthentication();
  return false;
}
// Uploads check the login at UPLOAD_FILE_START. A failed check used to only set a flag, so the web server still read
// the whole body: a fake upload sent slowly from any device on the Wi-Fi kept the single loop (and all DNS) busy.
// Now the connection is closed at once; the page logs in through /auth before every upload.
static bool uploadAuth(const char* what) {
  if (web.header(CSRF_HEADER) == CSRF_VALUE && checkPassword()) return true;
  Serial.printf("[%s] upload without a valid login: connection closed\n", what); web.client().stop(); return false;
}
static void handleBan() {                          // /ban?ip=x toggles the ban
  if (!requireAuth()) return;
  IPAddress ip; if (!ip.fromString(web.arg("ip"))) { web.send(400, "text/plain", "bad IP address"); return; }
  // The router forwards every device's lookups, so one click on its row used to block DNS for the whole house.
  if (ip == WiFi.gatewayIP() || ip == WiFi.localIP()) { web.send(400, "text/plain", "not banned: " + ip.toString() + " is the router or this device; banning it would block every device"); return; }
  const uint32_t a = (uint32_t)ip; const bool was = isBannedIP(a);
  if (was) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == a) { bannedIP[i] = bannedIP[--numBanned]; break; } }
  else if (numBanned < MAX_BAN) bannedIP[numBanned++] = a;
  else { web.send(400, "text/plain", "not banned: the ban list is full (32)"); return; }
  Dev* c = getClient(a); if (c) c->banned = !was;   // a row on the Devices tab, so it can be unbanned there
  saveBanned(); web.send(200, "text/plain", was ? "unbanned" : "banned");
}
static int buildQueryA(const String& d);
static void handleSetUpstream() {                   // /setupstream?u=1.1.1.3:250,1.0.0.3:250,94.140.14.15:700
  if (!requireAuth()) return;
  Upstream tmp[MAX_UPSTREAMS]; int n = 0; String err;
  if (!parseUpstreams(web.arg("u"), tmp, n, err)) { web.send(400, "text/plain", err); return; }
  // Probe each server with a real lookup first, so a setup where nothing answers (e.g. Single mode
  // with an address that never replies) can't be saved and make every lookup fail.
  String dead; int alive = 0;
  for (int i = 0; i < n; i++) {
    const int ql = buildQueryA("example.com"); memcpy(qsave, buf, ql);
    Upstream probe = tmp[i]; const char* why = "";      // a copy: the probe doesn't count in the stats
    if (askUpstream(probe, ql, ql - 12, &why) > 0) alive++;
    else { if (dead.length()) dead += ", "; dead += tmp[i].ip.toString() + " (" + why + ")"; }
  }
  if (!alive) { web.send(400, "text/plain", "not saved: no server answered a test lookup: " + dead); return; }
  dropPending();                                    // their upstream indexes are about to change
  for (int i = 0; i < n; i++) ups[i] = tmp[i];       // fresh entries: per-server stats start at 0
  numUps = n; totalFailovers = totalServfail = 0; saveUpstreams();
  Serial.printf("[upstream] %d server(s), first %s\n", numUps, ups[0].ip.toString().c_str());
  web.send(200, "text/plain", dead.length() ? "ok, but no answer from " + dead : String("ok"));
}

// ---------- domain test (dashboard "Test a domain") ----------
// A query for d in buf (random id, RD set). Returns its length, or 0 if a label is empty or too long.
static int buildQueryA(const String& d) {
  memset(buf, 0, 12); const uint16_t id = (uint16_t)esp_random(); buf[0] = id >> 8; buf[1] = id & 0xFF; buf[2] = 0x01; buf[5] = 1;
  int i = 12, start = 0;
  while (start < (int)d.length()) {
    int dot = d.indexOf('.', start); if (dot < 0) dot = d.length();
    const int l = dot - start; if (l < 1 || l > 63) return 0;
    buf[i++] = l; memcpy(buf + i, d.c_str() + start, l); i += l; start = dot + 1;
  }
  buf[i++] = 0; buf[i++] = 0; buf[i++] = 1; buf[i++] = 0; buf[i++] = 1;   // QTYPE A, QCLASS IN
  return i;
}
// Read a (possibly compressed) name at buf[i] into *out (if given); returns the index just past it.
static int dnsName(int i, int n, String* out) {
  int end = -1;
  for (int hops = 0; i < n && hops < 16; ) {
    const uint8_t l = buf[i];
    if (l == 0) { i++; break; }
    if ((l & 0xC0) == 0xC0) { if (i + 1 >= n) return n; if (end < 0) end = i + 2; i = ((l & 0x3F) << 8) | buf[i + 1]; hops++; continue; }
    if (out) { if (out->length()) *out += '.'; for (int k = 1; k <= l && i + k < n; k++) { char ch = buf[i + k]; *out += isprint((unsigned char)ch) && ch != '"' && ch != '\\' ? ch : '?'; } }
    i += l + 1;
  }
  return end >= 0 ? end : i;
}
// "CNAME x, 1.2.3.4" summary of the answer section of the reply in buf[0..n).
static String answersOf(int n) {
  String s; if (n < 12) return s;
  const int an = (buf[6] << 8) | buf[7]; int i = dnsName(12, n, nullptr) + 4;
  for (int a = 0; a < an && a < 8; a++) {
    i = dnsName(i, n, nullptr); if (i + 10 > n) break;
    const uint16_t type = (buf[i] << 8) | buf[i + 1], rdlen = (buf[i + 8] << 8) | buf[i + 9]; i += 10;
    if (i + rdlen > n) break;
    String v;
    if (type == 1 && rdlen == 4) v = IPAddress(buf[i], buf[i + 1], buf[i + 2], buf[i + 3]).toString();
    else if (type == 5) { String t; dnsName(i, n, &t); v = "CNAME " + t; }
    if (v.length()) { if (s.length()) s += ", "; s += v; }
    i += rdlen;
  }
  return s;
}
// /test?d=example.com -> what this device would answer for that name, and why. Unblocked names get a
// real upstream lookup, which holds the single DNS thread for up to the chain's worst case (hence auth).
static void handleTest() {
  if (!requireAuth()) return;
  String d = web.arg("d"); d.trim(); d.toLowerCase(); if (d.endsWith(".")) d.remove(d.length() - 1);
  bool ok = d.length() > 2 && d.length() < 250 && d.indexOf('.') > 0;
  for (char ch : d) if (!isalnum((unsigned char)ch) && ch != '.' && ch != '-' && ch != '_') ok = false;
  const int qlen = ok ? buildQueryA(d) : 0;
  if (!qlen) { web.send(400, "text/plain", "enter a domain like example.com"); return; }
  const String m = d.startsWith("www.") ? d.substring(4) : d;   // same www. stripping as parseQuery()
  const char* hit = ""; const Verdict v = classify(m.c_str(), &hit);
  static const char* const VN[] = {"upstream", "allowed", "custom-block", "blocklist"};
  String j = "{\"domain\":\"" + jesc(d) + "\",\"verdict\":\"" + VN[v] + "\",\"match\":\"" + jesc(hit) + "\",\"blocking\":" + (blockingOn ? "true" : "false");
  if (v < V_CUSTOM || !blockingOn) {                 // the DNS path would forward this name
    const uint32_t t0 = millis(); const int n = forwardUpstream(qlen, qlen, d.c_str());
    j += ",\"ms\":" + String(millis() - t0);
    if (lastUp >= 0) {
      static const char* const RC[] = {"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"};
      const uint8_t rc = buf[3] & 0x0F;
      j += ",\"upstream\":\"" + String(upName(ups[lastUp].ip)) + " " + ups[lastUp].ip.toString() + "\",\"filtered\":" + (upFiltered(ups[lastUp].ip) ? "true" : "false");
      j += ",\"rcode\":\""; j += rc < 6 ? RC[rc] : "other"; j += "\",\"answers\":\"" + answersOf(n) + "\"";
    } else j += ",\"upstream\":\"none: every server failed (SERVFAIL)\"";
  }
  web.send(200, "application/json", j + "}");
}

// ---------- blocklist swap (shared by upload + remote fetch) ----------
// The partition holds one list, so we free the old one before writing the new.
// While swapping, numHashes=0 -> device fail-opens (forwards, no blocking).
static void reopenBlocklist() {
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0;
  buildFlashIndex();
}
static void beginBlocklistSwap() {
  if (blocklist) blocklist.close();
  numHashes = 0;
  LittleFS.remove(BLOCKLIST_PATH);
  LittleFS.remove("/blocklist.new");
  LittleFS.remove("/blocklist.json");               // describes the old list; settings files are never touched
}
static bool commitNewBlocklist() {                  // /blocklist.new -> live (validated)
  File f = LittleFS.open("/blocklist.new", "r");
  size_t sz = f ? f.size() : 0; if (f) f.close();
  bool ok = sz > 0 && (sz % HASH_BYTES) == 0;       // sorted hash blob -> 5-byte multiple
  if (ok) LittleFS.rename("/blocklist.new", BLOCKLIST_PATH);
  else    LittleFS.remove("/blocklist.new");
  reopenBlocklist();
  return ok;
}

// ---------- OTA blocklist update (browser upload) ----------
static bool upOk = false;
static bool upAuthOk = false;
static bool upWriteErr = false;                     // storage full mid-upload: a cut-off list could still pass the size check
static File upFile;
static void handleUploadDone() {
  if (!upAuthOk) { web.requestAuthentication(); return; }
  web.send(upOk ? 200 : 500, "text/plain",
           upOk ? "ok" : "rejected: empty, size not a multiple of 5 (not a blocklist.bin?) or storage full. "
                         "The old list was already removed: upload a list again");
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      upAuthOk = uploadAuth("ota");
      if (!upAuthOk) break;
      upOk = false; upWriteErr = false; beginBlocklistSwap();
      upFile = LittleFS.open("/blocklist.new", "w");
      Serial.printf("[ota] receiving %s\n", u.filename.c_str());
      break;
    case UPLOAD_FILE_WRITE:
      if (upAuthOk && upFile && upFile.write(u.buf, u.currentSize) != u.currentSize) { upWriteErr = true; upFile.close(); }
      break;
    case UPLOAD_FILE_END:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      if (upWriteErr) LittleFS.remove("/blocklist.new");
      upOk = commitNewBlocklist();
      Serial.printf("[ota] %s -> %u domains\n", upOk ? "OK" : "REJECTED", numHashes);
      break;
    case UPLOAD_FILE_ABORTED:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      LittleFS.remove("/blocklist.new"); reopenBlocklist();
      Serial.println("[ota] aborted");
      break;
  }
}

// ---------- blocklist metadata (blocklist.json from tools/update.py, shown in the dashboard) ----------
static const size_t META_MAX = 4096;
static bool metaOk = false, metaAuthOk = false;
static size_t metaSize = 0;
static File metaFile;
static void handleMetaDone() {
  if (!metaAuthOk) { web.requestAuthentication(); return; }
  web.send(metaOk ? 200 : 400, "text/plain", metaOk ? "ok" : "rejected: empty or larger than 4 KB");
}
static void handleMetaUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      metaAuthOk = uploadAuth("meta");
      metaOk = false; metaSize = 0;
      if (metaAuthOk) metaFile = LittleFS.open("/blocklist.json.new", "w");
      break;
    case UPLOAD_FILE_WRITE:
      if (!metaAuthOk || !metaFile) break;
      metaSize += u.currentSize; if (metaSize <= META_MAX) metaFile.write(u.buf, u.currentSize);
      break;
    case UPLOAD_FILE_END:
      if (!metaAuthOk) break;
      if (metaFile) metaFile.close();
      metaOk = metaSize > 1 && metaSize <= META_MAX;
      if (metaOk) { LittleFS.remove("/blocklist.json"); LittleFS.rename("/blocklist.json.new", "/blocklist.json"); }
      else LittleFS.remove("/blocklist.json.new");
      break;
    case UPLOAD_FILE_ABORTED:
      if (metaFile) metaFile.close();
      LittleFS.remove("/blocklist.json.new");
      break;
  }
}

// ---------- firmware OTA (browser upload of firmware.bin -> reboot) ----------
static bool fwAuthOk = false;
static void handleFwUpdateDone() {
  if (!fwAuthOk) { web.requestAuthentication(); return; }
  bool ok = !Update.hasError();
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    fwAuthOk = uploadAuth("fw-ota");
    if (!fwAuthOk) return;
    markFirmwareGood("it accepted the next update");   // running well enough to take one; keeps the rollback target simple
    Serial.printf("[fw-ota] %s\n", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (!fwAuthOk) return;
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (!fwAuthOk) return;
    if (Update.end(true)) Serial.printf("[fw-ota] %u bytes OK\n", u.totalSize);
    else Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    if (!fwAuthOk) return;
    Update.abort(); Serial.println("[fw-ota] aborted");
  }
}

// ---------- WiFi provisioning (captive portal) ----------
// Try provisioned NVS creds first, then the compile-time secrets.h creds as a
// fallback (so the maintainer's own device + source builders keep working). If
// neither connects, fall through to the config portal.
static bool hasCreds() {
  prefs.begin("wifi", true); bool nvs = prefs.getString("ssid", "").length() > 0; prefs.end();
  return nvs || (WIFI_SSID && *WIFI_SSID && strcmp(WIFI_SSID, "YOUR_WIFI_SSID") != 0);
}
static bool connectWiFi() {
  prefs.begin("wifi", true);
  String ss = prefs.getString("ssid", "");
  String pw = prefs.getString("pass", "");
  prefs.end();
  const char* ssid = ss.length() ? ss.c_str() : WIFI_SSID;
  const char* pass = ss.length() ? pw.c_str() : WIFI_PASS;
  if (!ssid || !*ssid || strcmp(ssid, "YOUR_WIFI_SSID") == 0) return false;  // unconfigured
  Serial.printf("WiFi: connecting to \"%s\"%s\n", ssid, ss.length() ? " (provisioned)" : " (secrets.h)");
  WiFi.mode(WIFI_STA); WiFi.setSleep(false); WiFi.begin(ssid, pass);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 30000) { delay(250); Serial.print("."); }
  Serial.println();
  return WiFi.status() == WL_CONNECTED;
}

static void handlePortalRoot() {
  String html =
    "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>C3 AdBlock setup</title>"
    "<body style='font:16px system-ui,sans-serif;max-width:420px;margin:36px auto;padding:0 16px;background:#0d1117;color:#c9d1d9'>"
    "<h2>&#128737; C3 AdBlock &mdash; WiFi setup</h2>"
    "<p style='color:#8b949e'>Pick your network and enter its password. The device restarts and joins it.</p>"
    "<form method=POST action=/wifisave>"
    "<input list=nets name=s placeholder='WiFi name' required style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<datalist id=nets>" + portalOpts + "</datalist>"
    "<input name=p type=password placeholder='Password' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<button style='width:100%;padding:12px;margin-top:8px;border-radius:6px;border:0;background:#3fb950;color:#000;font-weight:600;cursor:pointer'>Connect</button>"
    "</form></body>";
  web.send(200, "text/html", html);
}
static void handleWifiSave() {
  String ss = web.arg("s"), pw = web.arg("p");
  if (!ss.length()) { web.send(400, "text/plain", "missing WiFi name"); return; }
  prefs.begin("wifi", false); prefs.putString("ssid", ss); prefs.putString("pass", pw); prefs.end();
  web.send(200, "text/html", "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                             "&#9989; Saved. Restarting and joining <b>" + htmlEscape(ss) + "</b>&hellip;<br><br>"
                             "Reconnect your phone to your normal WiFi, then find the box at <b>c3adblock.local</b>.</body>");
  delay(900); ESP.restart();
}
// Never returns — blocks in the portal loop until creds are saved (then reboots).
static void startConfigPortal() {
  int n = WiFi.scanNetworks();                 // scan while still in STA mode (no APSTA)
  portalOpts = "";
  for (int i = 0; i < n && i < 15; i++) portalOpts += "<option value='" + htmlEscape(WiFi.SSID(i)) + "'>";
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[24]; snprintf(ap, sizeof(ap), "C3-AdBlock-%02X%02X", mac[4], mac[5]);
  WiFi.mode(WIFI_AP); WiFi.softAP(ap);
  IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);              // catch-all -> phones pop the captive portal
  web.on("/", handlePortalRoot);
  web.on("/wifisave", HTTP_POST, handleWifiSave);
  web.onNotFound(handlePortalRoot);            // any captive-portal probe -> the form
  web.begin();
  Serial.printf("\n[setup] No WiFi. Join open network \"%s\" and a setup page pops up (or http://%s)\n",
                ap, apIP.toString().c_str());
  // A configured device that merely failed to join (router rebooting, weak signal) must not
  // get stuck here: if nobody is using the portal, reboot and retry WiFi every 3 minutes.
  const bool configured = hasCreds();
  uint32_t t0 = millis();
  while (true) {
    dnsPortal.processNextRequest(); web.handleClient(); delay(2);
    if (WiFi.softAPgetStationNum() > 0) t0 = millis();          // someone is setting it up
    if (configured && millis() - t0 > 180000UL) { Serial.println("[setup] retrying WiFi"); ESP.restart(); }
  }
}

void setup() {
  Serial.begin(115200); delay(300);
  Serial.printf("\n[c3-adblock] booting (last reset: %s)\n", resetReason());
  { esp_ota_img_states_t st; fwPending = esp_ota_get_state_partition(esp_ota_get_running_partition(), &st) == ESP_OK && st == ESP_OTA_IMG_PENDING_VERIFY; }
  if (fwPending) Serial.println("[fw-ota] new firmware: not confirmed until it answers a lookup (a restart before that rolls back)");
  if (!LittleFS.begin(true)) Serial.println("LittleFS FAILED");
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  if (blocklist) {
    numHashes = blocklist.size() / HASH_BYTES;
    Serial.printf("blocklist: %u domains\n", numHashes);
    buildFlashIndex();
  }
  loadCustom(); loadAllow(); loadBanned(); loadUpstreams(); loadFilterCfg();
  Serial.printf("custom: %d, allow: %d, banned: %d, upstreams: %d (first %s), local list %s\n", numCustom, numAllow, numBanned, numUps, ups[0].ip.toString().c_str(), listOn ? "on" : "off");

  // Hold BOOT at power-on to wipe saved WiFi and force the setup portal.
#if CONFIG_IDF_TARGET_ESP32C3
  const int BOOT_PIN = 9;     // C3 BOOT button
#else
  const int BOOT_PIN = 0;     // classic ESP32 BOOT button (GPIO9 is a flash pin there)
#endif
  pinMode(BOOT_PIN, INPUT_PULLUP);
  if (digitalRead(BOOT_PIN) == LOW) { delay(60);
    if (digitalRead(BOOT_PIN) == LOW) { prefs.begin("wifi", false); prefs.clear(); prefs.end();
      Serial.println("[setup] BOOT held -> cleared saved WiFi"); } }

  // After a power cut the router can take minutes to bring Wi-Fi back, and the open setup portal used to come up
  // after a single 30 s try (anyone nearby could join it and point the device elsewhere). With saved details,
  // keep trying for ~5 min first; with nothing saved the portal still opens straight away.
  bool joined = connectWiFi();
  for (int i = 1; !joined && i < 10 && hasCreds(); i++) { Serial.printf("[wifi] retry %d/9\n", i); WiFi.disconnect(); delay(500); joined = connectWiFi(); }
  if (!joined) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());
  if (MDNS.begin("c3adblock")) { MDNS.addService("http", "tcp", 80); Serial.println("dashboard: http://c3adblock.local"); }

  if (strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0)
    Serial.println("[WARN] secrets.h still has placeholder WEB_PASS/OTA_PASS — those are public "
                    "(they're in the repo's example file). Set real values before trusting this "
                    "device on a network you don't fully control.");

  dnsServer.begin(DNS_PORT); probeCli.begin(0); for (WiFiUDP& s : upSock) s.begin(0);
  { const char* hdrs[] = { CSRF_HEADER }; web.collectHeaders(hdrs, 1); }  // needed for requireAuth()'s CSRF check
  // DNS rebinding: a page on a public domain whose name is later pointed at 192.168.1.10 could read /stats.json.
  // Answer only host names that can't come from the internet: this IP, one label, or .local/.lan/.home/.internal.
  web.addMiddleware([](WebServer& s, Middleware::Callback next) {
    String h = s.hostHeader(); h.toLowerCase(); const int c = h.indexOf(':'); if (c >= 0) h.remove(c);
    if (!h.length() || h == WiFi.localIP().toString() || h.indexOf('.') < 0 || h.endsWith(".local") || h.endsWith(".lan") ||
        h.endsWith(".home") || h.endsWith(".internal") || h.endsWith(".home.arpa")) return next();
    s.send(421, "text/plain", "wrong host name: open http://c3adblock.local"); return true;
  });
  web.on("/", []() {                         // no framing: another site could show the dashboard in a frame and trick clicks
    web.sendHeader("Cache-Control", "no-store"); web.sendHeader("X-Frame-Options", "DENY");
    web.sendHeader("Content-Security-Policy", "frame-ancestors 'none'"); web.send_P(200, "text/html", PAGE); });
  web.on("/stats.json", handleStats);
  web.on("/ban", handleBan);
  web.on("/setupstream", handleSetUpstream);
  web.on("/setlist", []() {                  // /setlist?on=1|0 : local blocklist on/off as a filter
    if (!requireAuth()) return;
    listOn = web.arg("on") != "0"; saveFilterCfg();
    Serial.printf("[filter] local list %s\n", listOn ? "on" : "off");
    web.send(200, "text/plain", listOn ? "local list on" : "local list off");
  });
  web.on("/addblock", []() { if (!requireAuth()) return; bool ok = addCustom(web.arg("d")); web.send(ok ? 200 : 400, "text/plain", ok ? "ok" : NOT_ADDED); });
  web.on("/unblock", []() { if (!requireAuth()) return; removeCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/addallow", []() { if (!requireAuth()) return; bool ok = addAllow(web.arg("d")); web.send(ok ? 200 : 400, "text/plain", ok ? "ok" : NOT_ADDED); });
  web.on("/unallow", []() { if (!requireAuth()) return; removeAllow(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/test", handleTest);
  web.on("/auth", []() { if (requireAuth()) web.send(200, "text/plain", "ok"); });   // the page logs in here before uploads
  web.on("/uploadmeta", HTTP_POST, handleMetaDone, handleMetaUpload);  // blocklist.json (auth inside)
  web.on("/blocklist.json", HTTP_GET, []() {
    File f = LittleFS.open("/blocklist.json", "r");
    if (!f) { web.send(404, "text/plain", "no metadata"); return; }
    web.streamFile(f, "application/json"); f.close();
  });
  web.on("/pause", []() {                    // /pause?s=300  (0 or absent = indefinite)
    if (!requireAuth()) return;
    long s = web.hasArg("s") ? web.arg("s").toInt() : 0; if (s > 86400) s = 86400;   // longer wrapped millis() and resumed at once
    blockingOn = false; resumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
    web.send(200, "text/plain", "paused");
  });
  web.on("/resume", []() { if (!requireAuth()) return; blockingOn = true; resumeAt = 0; web.send(200, "text/plain", "resumed"); });
  web.on("/forgetwifi", []() { if (!requireAuth()) return; web.send(200, "text/plain", "cleared — rebooting into setup portal");
    prefs.begin("wifi", false); prefs.clear(); prefs.end(); delay(500); ESP.restart(); });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);      // blocklist OTA (auth inside handleUpload)
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);  // firmware OTA (auth inside handleFwUpload)
  web.begin();
  ArduinoOTA.setHostname("c3adblock");   // pio run -t upload --upload-port c3adblock.local
  ArduinoOTA.setPassword(OTA_PASS);      // network OTA was unauthenticated upstream
  ArduinoOTA.begin();
  Serial.println("DNS :53 + dashboard :80 + OTA up");
}

void loop() {
  ArduinoOTA.handle();
  web.handleClient();
  bool busy = handleDns();
  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) { blockingOn = true; resumeAt = 0; }
  if (fwPending && millis() > 600000UL) markFirmwareGood("10 min uptime");
  rotatePorts();
  if (!busy) delay(1);   // sleep only when idle: full speed under load, cool when quiet
}

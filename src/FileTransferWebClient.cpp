#include "FileTransferConfig.h" // switches first -- every guard below depends on it

#ifdef OPENKNX_FTC_KNXOTA_WEB
    #include "FileTransferWebClient.h"
    #include "FileTransferClient.h"
    #include "webassets.h"
    #include <LittleFS.h>
    #ifdef OPENKNX_SDCARD
        #include "SdFileStore.h"
    #endif
    #ifdef OPENKNX_EXTFLASH
        #include "EfcFileStore.h"
    #endif
    #include "OpenKNX/Network/Webserver/BoundedText.h"
    #include "knx/config.h"
    #ifdef KNX_HAS_TP
        #include "knx.h"
    #endif

FileTransferWebClient openknxFtcWeb;

using OpenKNX::Network::BoundedText;
using OpenKNX::Network::WebRequest;
using OpenKNX::Network::WebResponse;
using OpenKNX::Network::Webserver;
using OpenKNX::Network::WEB_GET;
using OpenKNX::Network::WEB_POST;

// "5.0.3" -> 0x5003. Returns 0 for anything that is not three numbers, so a typo cannot become 0.0.0.
uint16_t FileTransferWebClient::parsePa(const std::string &s)
{
    unsigned a = 0, l = 0, d = 0;
    if (FTC_SSCANF(s.c_str(), "%u.%u.%u", &a, &l, &d) != 3) return 0;
    if (a > 15 || l > 15 || d > 255) return 0;
    return (uint16_t)((a << 12) | (l << 8) | d);
}

std::string FileTransferWebClient::paText(uint16_t pa)
{
    char b[16];
    snprintf(b, sizeof(b), "%u.%u.%u", (pa >> 12) & 0x0F, (pa >> 8) & 0x0F, pa & 0xFF);
    return b;
}

// Device text goes into JSON: one stray quote or backslash from a path would break the whole answer.
// Writes at most 2 * strlen(v) + 1 bytes; out of cap bytes, never more.
static const char *jsonEsc(char *out, size_t cap, const char *v)
{
    size_t n = 0;
    for (const char *p = v; p && *p && n + 2 < cap; p++)
    {
        if ((uint8_t)*p < 0x20) continue;
        if (*p == '"' || *p == '\\') out[n++] = '\\';
        out[n++] = *p;
    }
    out[n] = '\0';
    return out;
}

// The same, straight into the answer
static void addJsonEsc(BoundedText &t, const char *v)
{
    for (const char *p = v; p && *p; p++)
    {
        if ((uint8_t)*p < 0x20) continue;
        if (*p == '"' || *p == '\\') t += '\\';
        t += *p;
    }
}

// Sizes the way the file manager shows them -- a raw byte count says little about a 1 MB image.
static void fmtSize(char *t, size_t len, uint32_t b)
{
    if (b >= 1048576u) snprintf(t, len, "%.1f MB", b / 1048576.0);
    else if (b >= 1024u) snprintf(t, len, "%.1f KB", b / 1024.0);
    else snprintf(t, len, "%u B", (unsigned)b);
}

// The /knxota/status answer in parts. Its size bound (ST_FIXED, ST_PER_HIT) is built from these formats: every
// conversion takes 2 format bytes or more, so sizeof(format) plus the widest value of each field covers the text.
static const char ST_MAIN[] = "{\"phase\":\"%s\",\"busy\":%s,\"ok\":%s,\"unconfirmed\":%s,\"message\":\"%s\","
                              "\"done\":%u,\"total\":%u,\"bps\":%u,\"chunk\":%u,\"chunks\":%u,"
                              "\"window\":%u,\"windowState\":%u,\"target\":\"%s\","
                              "\"resends\":%u,\"verifies\":%u,\"crcErrors\":%u";
static const char ST_BAUD[] = ",\"baud\":%d";
static const char ST_AUTH[] = ",\"auth\":{\"state\":\"%s\",\"wait\":%u,\"pa\":\"%s\"}";
// `feat` stays what the device REPORTED; `can` is what it can, which on a legacy server
// is derived from its version because it has no CheckFeatures to answer with. The page
// greys out on `can` and shows `legacy` -- otherwise a zero byte reads as "can nothing".
static const char ST_DEV[] = ",\"dev\":{\"pa\":\"%s\",\"cls\":\"%s\",\"mask\":%u,\"ftm\":%u,\"feat\":%u,"
                             "\"can\":%u,\"legacy\":%s,\"derived\":%s,"
                             "\"prog\":%s,\"mfr\":%u,\"apdu\":%u,\"router\":%s";
static const char ST_ORDER[] = ",\"order\":\"%s\"";
static const char ST_APPVER[] = ",\"appVer\":\"%u.%u\"";
static const char ST_SERIAL[] = ",\"serial\":\"%02X %02X %02X %02X %02X %02X\"";
static const char ST_HW[] = ",\"hw\":\"%02X %02X %02X %02X %02X %02X\"";
static const char ST_VOLT[] = ",\"volt\":%u";
static const char ST_TABS[] = ",\"tabs\":[%u,%u,%u,%u]}";
static const char ST_SCAN[] = ",\"scan\":{\"running\":%s,\"complete\":%s,\"found\":%u,\"max\":%u,\"at\":\"%s\","
                              "\"done\":%u,\"total\":%u,\"hits\":[";
static const char ST_HIT[] = "%s{\"pa\":\"%s\",\"mask\":%u,\"ok\":%s,\"id\":\"%s\"}";
static const char ST_DRIVE[] = "%s{\"state\":%u,\"total\":%u,\"free\":%u,\"kb\":%s}";
static const char ST_DRIVES[] = "]},\"drives\":[],\"drivesPa\":\"%s\",\"drivesBusy\":%s"; // hits end, drives open, drives end: bound only
static const char ST_GA[] = ",\"ga\":{\"pa\":\"%s\",\"lost\":%s,\"cut\":%s,\"n\":%u,\"ver\":%lu}"; // rows: /knxota/garows
static const char ST_GA_ROW[] = "%s{\"ga\":%u,\"co\":%u,\"flags\":%u,\"prio\":%u,\"size\":%u,\"cfg\":%s,\"unk\":%s}";
static const char ST_RESULT[] = ",\"result\":{\"kind\":%u,\"ok\":%s,\"pa\":\"%s\",\"bytes\":%u,\"chunks\":%u,"
                                "\"ms\":%u,\"bps\":%u,\"verify\":%u,\"mode\":%u,\"resumed\":%u,\"retries\":%u,"
                                "\"cleanup\":%u,\"file\":\"%s\",\"apply\":%s}";
static const char ST_END[] = "}"; // answer end: bound only

// Widest value per conversion: "false" or "upload" 6, a PA "15.15.255" 9, 32 bit 10, 16 bit 5, 8 bit 3, int 11
static constexpr size_t W_WORD = 6, W_PA = 9, W_U32 = 10, W_U16 = 5, W_U8 = 3, W_INT = 11;
static constexpr size_t esc(size_t field) { return 2 * (field - 1); } // a char[] field, escaped
static constexpr size_t ST_FIXED =
    sizeof(ST_MAIN) + 4 * W_WORD + esc(sizeof(FtcStatus::message)) + 2 * W_U32 + 4 * W_U16 + W_U8 + W_PA + 3 * W_U16 +
    sizeof(ST_BAUD) + W_INT +
    sizeof(ST_AUTH) + W_WORD + 2 + W_U16 + W_PA + // "noanswer" is 8
    sizeof(ST_DEV) + W_PA + esc(sizeof(FtcDeviceInfo::cls)) + 2 * W_U16 + W_U32 + W_U8 + 3 * W_WORD + 2 * W_U16 + W_WORD +
    sizeof(ST_ORDER) + esc(sizeof(FtcDeviceInfo::order)) + sizeof(ST_APPVER) + 2 * W_U8 + sizeof(ST_SERIAL) + sizeof(ST_HW) +
    sizeof(ST_VOLT) + W_U16 + sizeof(ST_TABS) + 4 * W_U8 +
    sizeof(ST_SCAN) + 2 * W_WORD + 2 * W_U16 + W_PA + 2 * W_U32 +
    sizeof(ST_DRIVES) + W_PA + W_WORD + 3 * (sizeof(ST_DRIVE) + W_U8 + 2 * W_U32 + W_WORD) +
    sizeof(ST_GA) + W_PA + 2 * W_WORD + W_U16 + W_U32 +
    sizeof(ST_RESULT) + W_U8 + W_WORD + W_PA + W_U32 + W_U16 + 2 * W_U32 + 2 * W_U8 + W_U32 + W_U16 + W_U8 +
    esc(sizeof(FtcTransferSetup::local)) + W_WORD +
    sizeof(ST_END);
static constexpr size_t ST_PER_HIT = sizeof(ST_HIT) + 1 + W_PA + W_U16 + W_WORD + esc(sizeof(FtcEntry::okId));
static constexpr size_t ST_PER_GA = sizeof(ST_GA_ROW) + 1 + 2 * W_U16 + 3 * W_U8 + 2 * W_WORD;

// /knxota/garows: at most GA_PAGE_ROWS rows per answer; a 4.1 KB block for at most 3.4 KB of text
static const char GA_PAGE[] = "{\"pa\":\"%s\",\"from\":%u,\"n\":%u,\"ver\":%lu,\"rows\":[";
static constexpr uint16_t GA_PAGE_ROWS = 40;
static constexpr size_t GA_PAGE_FIXED = sizeof(GA_PAGE) + W_PA + 2 * W_U16 + W_U32 + sizeof("]}");

/** @brief Version of the group-address rows: the page fetches them again only when it changes (read running, new read). */
static uint32_t gaVersion(const FtcGaEntry *ga, uint16_t n, uint16_t pa, bool cut)
{
    uint32_t h = 2166136261u;
    auto mix = [&h](uint32_t v) { h = (h ^ v) * 16777619u; };
    mix(pa | (uint32_t)n << 16);
    mix(cut ? 1 : 0);
    for (uint16_t i = 0; i < n; i++)
    {
        mix(ga[i].ga | (uint32_t)ga[i].co << 16);
        mix(ga[i].flags | (uint32_t)ga[i].prio << 8 | (uint32_t)ga[i].sizeCode << 16 | (uint32_t)ga[i].cfgValid << 24 |
            (uint32_t)ga[i].gaUnknown << 25);
    }
    return h;
}

// /knxota/files: one block of at most this size; files beyond it are left out and the answer carries X-List-Cut
    #ifndef OPENKNX_FTC_WEB_FILES_BUF
        #ifdef ARDUINO_ARCH_RP2040
            #define OPENKNX_FTC_WEB_FILES_BUF 4096
        #else
            #define OPENKNX_FTC_WEB_FILES_BUF 16384
        #endif
    #endif

// ── Page ───────────────────────────────────────────────────────────────────────────────────────
void FileTransferWebClient::handlePage(WebRequest &req, WebResponse &res)
{
    // Only the shell. The page's markup lives in knxota.js, which sits gzipped in flash -- the same
    // text costs a third of what a string literal here costs (measured: 9836 B -> 2641 B). The build
    // switches travel as data attributes, because the script builds the page before the first poll.
    std::string h = "<div id='ota' data-sec='";
#ifdef OPENKNX_FTC_SECURITY
    h += "1";
#else
    h += "0";
#endif
    h += "' data-sd='";
#ifdef OPENKNX_SDCARD
    h += "1";
#else
    h += "0";
#endif
    h += "' data-efc='";
#ifdef OPENKNX_EXTFLASH
    h += "1";
#else
    h += "0";
#endif
    h += "'></div>";

    res.setLayout(true);              // the shared frame: sidebar, menu, stylesheets
    res.setActiveMenu("/knxota");
    res.send(h.c_str());
}


// ── Scan hits: kept here, because the client releases its listing when the sweep ends ──────────
void FileTransferWebClient::collectScanHits()
{
    auto *c = FileTransferClient::instance();
    const auto &st = c->status();
    if (st.phase != FtcPhase::Scan)
    {
        // The sweep just ended: remember that it reached its end and keep the last progress pair, so a
        // page opened afterwards still learns the outcome instead of seeing zeros.
        if (_scanWasRunning)
        {
            _scanWasRunning = false;
            _scanDone = st.ok;
        }
        return;
    }
    if (!_scanWasRunning)
    {
        // A sweep started that this class did not start (console `ftc scan`): its hits would otherwise
        // be appended to the list of the previous one, and both would be shown as the last search.
        _scanWasRunning = true;
        _scanDone = false;
        _scanHits.clear();
        _scanWasRunning = true; // this class starts it: do not let collectScanHits() clear it again
        _scanDone = false;
        _scanLastDone = _scanLastTotal = 0;
    }
    _scanLastDone = st.done;
    _scanLastTotal = st.total;
    for (const FtcEntry &e : c->listing())
    {
        const uint16_t pa = parsePa(e.name); // the sweep stores the PA as text in name[]
        if (!pa) continue;
        bool seen = false;
        for (ScanHit &h : _scanHits)
            if (h.pa == pa)
            {
                h.openKnx = h.openKnx || e.isOpenKnx; // the flag arrives in the post-sweep probe
                if (e.okId[0] && !h.okId[0]) strncpy(h.okId, e.okId, sizeof(h.okId) - 1);
                seen = true;
                break;
            }
        if (!seen && _scanHits.size() < SCAN_HIT_MAX)
        {
            _scanHits.push_back({pa, (uint16_t)e.crc, e.isOpenKnx, {0}}); // the sweep parks the mask in crc
            strncpy(_scanHits.back().okId, e.okId, sizeof(_scanHits.back().okId) - 1);
        }
    }
}


// ── Drives: three separate FilesystemInfo commands, one per drive ──────────────────────────────
// A target without that drive ignores the prefix and answers with its internal filesystem, so the
// status byte is the only discriminator: 0x01 = a provider answered (KB), 0x00 = the internal one.
void FileTransferWebClient::collectDriveAnswer()
{
    if (_dfPending < 0) return;
    auto *c = FileTransferClient::instance();
    if (c->isBusy()) return; // still in flight
    const FtcFsInfo &f = c->fsInfo();
    DriveInfo &d = _drv[_dfPending];
    if (!f.valid) d.state = 1;                       // no usable answer -> treat as absent
    else if (_dfPending != 0 && !f.kb) d.state = 1;  // asked for sd//efc/, got the internal FS
    else
    {
        d.total = f.total;
        d.free = f.free;
        d.kb = f.kb;
        d.state = (f.total == 0) ? 3 : 2;
    }
    _dfPending = -1;
}


// ── Status: what the client really holds -- no field is served that is not backed by its state ─
void FileTransferWebClient::handleStatus(WebRequest &req, WebResponse &res)
{
    static_assert(sizeof(ScanHit::okId) == sizeof(FtcEntry::okId), "ST_PER_HIT sizes a hit with FtcEntry::okId");
    auto *c = FileTransferClient::instance();
    const FtcStatus &s = c->status();
    collectScanHits();
    collectDriveAnswer();

    const char *ph = "idle";
    switch (s.phase)
    {
        case FtcPhase::Ping: ph = "ping"; break;
        case FtcPhase::List: ph = "list"; break;
        case FtcPhase::Info: ph = "info"; break;
        case FtcPhase::Delete: ph = "delete"; break;
        case FtcPhase::Upload: ph = "upload"; break;
        case FtcPhase::Verify: ph = "verify"; break;
        case FtcPhase::Scan: ph = "scan"; break;
        case FtcPhase::Done: ph = "done"; break;
        case FtcPhase::Failed: ph = "failed"; break;
        default: break;
    }

    // One block for the whole answer, sized before it is written: polled every 0.9 s, it must not grow a string
    uint16_t gaN = 0;
    const FtcGaEntry *ga = c->groupObjects(gaN);
    const bool gaShown = !(_gaLost && _gaPa);
    if (!gaShown) gaN = 0;
    BoundedText out(ST_FIXED + _scanHits.size() * ST_PER_HIT);
    if (out.failed())
    {
        res.sendOutOfMemory();
        return;
    }
    char esc1[2 * FTC_PATH_MAX];
    out.addf(ST_MAIN, ph, c->isBusy() ? "true" : "false", s.ok ? "true" : "false", s.unconfirmed ? "true" : "false",
             jsonEsc(esc1, sizeof(esc1), s.message), (unsigned)s.done, (unsigned)s.total, (unsigned)s.bps,
             (unsigned)s.chunk, (unsigned)s.chunks, (unsigned)s.window, (unsigned)s.windowState,
             paText(s.target).c_str(), (unsigned)s.resends, (unsigned)s.verifies, (unsigned)s.crcErrors);

#ifdef KNX_HAS_TP
    // The baud rate of this device's bus chip bounds the rate a transfer reaches; the page forecasts with it.
    if (TpUartDataLinkLayer *dll = KNX_TP_DLL)
        out.addf(ST_BAUD, dll->getTPUart().getBaudrate());
#endif

#ifdef OPENKNX_FTC_SECURITY
    // What became of a login. The page cannot learn this from the POST -- that one only ARMS the
    // exchange, and answering it later would hold a web handler open across three bus round trips.
    // So the answer travels the way every other result does: through the status the page already polls.
    // The PA rides along, so a block left over from an earlier target is inert instead of misleading.
    {
        const char *as = "none";
        switch (c->authOutcome())
        {
            case FileTransferClient::FtcAuthOk: as = "ok"; break;
            case FileTransferClient::FtcAuthBadPw: as = "badpw"; break;
            case FileTransferClient::FtcAuthNotNeeded: as = "nopw"; break;
            case FileTransferClient::FtcAuthNoAnswer: as = "noanswer"; break;
            default: break;
        }
        out.addf(ST_AUTH, as, (unsigned)c->authBackoffSeconds(), paText(_authPa).c_str());
    }
#endif

    // What the target answered about itself. Only reported while it still belongs to the PA the page
    // asked for -- any other operation in between makes it stale, and a stale feature byte would put a
    // wrong answer on the password question.
    const FtcDeviceInfo &d = c->deviceInfo();
    const bool devFresh = d.valid && _featPa && s.target == _featPa;
    if (devFresh)
    {
        out.addf(ST_DEV, paText(_featPa).c_str(), jsonEsc(esc1, sizeof(esc1), d.cls), (unsigned)d.mask,
                 (unsigned)d.ftmVersion, (unsigned)d.features, (unsigned)d.ftmCan, d.ftmLegacy ? "true" : "false",
                 d.ftmDerived ? "true" : "false", d.progMode ? "true" : "false", (unsigned)d.manufacturer,
                 (unsigned)d.maxApdu, d.isRouter ? "true" : "false");
        if (d.haveOrder) out.addf(ST_ORDER, jsonEsc(esc1, sizeof(esc1), d.order));
        if (d.haveVersion) out.addf(ST_APPVER, (unsigned)((d.version >> 6) & 0x1F), (unsigned)(d.version & 0x3F));
        if (d.haveSerial)
            out.addf(ST_SERIAL, d.serial[0], d.serial[1], d.serial[2], d.serial[3], d.serial[4], d.serial[5]);
        if (d.haveHw)
            out.addf(ST_HW, d.hardware[0], d.hardware[1], d.hardware[2], d.hardware[3], d.hardware[4], d.hardware[5]);
        if (d.haveBusVolt) out.addf(ST_VOLT, (unsigned)d.busVoltmV);
        out.addf(ST_TABS, (unsigned)d.appState, (unsigned)d.addrTableState, (unsigned)d.assocTableState,
                 (unsigned)d.goTableState);
    }

    out.addf(ST_SCAN, s.phase == FtcPhase::Scan ? "true" : "false",
             // Whether the sweep ran to its end is the device's fact: a page that reloads mid-scan has
             // no way to know it otherwise, and that is exactly the case this view advertises.
             (s.phase != FtcPhase::Scan && _scanDone) ? "true" : "false", (unsigned)c->scanFound(),
             (unsigned)SCAN_HIT_MAX, paText(c->scanCurrentPa()).c_str(),
             (unsigned)(s.phase == FtcPhase::Scan ? s.done : _scanLastDone),
             (unsigned)(s.phase == FtcPhase::Scan ? s.total : _scanLastTotal));
    for (size_t i = 0; i < _scanHits.size(); i++)
        out.addf(ST_HIT, i ? "," : "", paText(_scanHits[i].pa).c_str(), (unsigned)_scanHits[i].mask,
                 _scanHits[i].openKnx ? "true" : "false", jsonEsc(esc1, sizeof(esc1), _scanHits[i].okId));
    out += "]}";

    // The target's drives, as far as they were asked for. Never a guess: state 0 means "not asked".
    out += ",\"drives\":[";
    for (int i = 0; i < 3; i++)
        out.addf(ST_DRIVE, i ? "," : "", (unsigned)_drv[i].state, (unsigned)_drv[i].total, (unsigned)_drv[i].free,
                 _drv[i].kb ? "true" : "false");
    out.addf("],\"drivesPa\":\"%s\",\"drivesBusy\":%s", paText(_drvPa).c_str(), _dfPending >= 0 ? "true" : "false");

    // Group addresses: served straight from the client, because it keeps them -- but its storage is
    // shared with the fast-upload bitmap, so a transfer invalidates them and the page says so.
    // "cut" is what the console prints as INCOMPLETE: the rows are a PREFIX of the device's tables.
    // Without it the page showed a partial read as a complete one - the failure this flag exists for.
    const bool gaCut = c->groupObjectsTruncated();
    out.addf(ST_GA, paText(_gaPa).c_str(), gaShown ? "false" : "true", gaCut ? "true" : "false", (unsigned)gaN,
             (unsigned long)gaVersion(ga, gaN, _gaPa, gaCut));

    // The finished job, for the summary. Set once at the end of a transfer and kept until the next one.
    const FtcTransferResult &r = c->transferResult();
    const FtcTransferSetup &u = c->transferSetup();
    if (r.valid)
        out.addf(ST_RESULT, (unsigned)r.kind, r.ok ? "true" : "false", paText(r.target).c_str(), (unsigned)r.bytes,
                 (unsigned)r.chunks, (unsigned)r.elapsedMs, (unsigned)r.avgBps, (unsigned)r.verify, (unsigned)r.mode,
                 (unsigned)r.resumedBytes, (unsigned)r.retries, (unsigned)r.cleanup,
                 jsonEsc(esc1, sizeof(esc1), u.valid ? u.local : ""), u.willApply ? "true" : "false");

    out += "}";
    if (out.cut())
    {
        // the bound above is wrong: a cut JSON would only break the page
        logError("knxOTA", "status answer exceeds its bound (%u B)", (unsigned)out.size());
        res.sendOutOfMemory();
        return;
    }
    res.setContentType("application/json");
    int len = 0;
    uint8_t *body = out.take(len);
    res.sendOwned(body, len);
}


// ── Group-address rows in pages; the status carries only their count and version ─────────────────
void FileTransferWebClient::handleGaRows(WebRequest &req, WebResponse &res)
{
    auto *c = FileTransferClient::instance();
    uint16_t gaN = 0;
    const FtcGaEntry *ga = c->groupObjects(gaN);
    if (_gaLost && _gaPa) gaN = 0; // a fast transfer reused the storage
    unsigned long from = strtoul(req.getQueryParam("from").c_str(), nullptr, 10);
    if (from > gaN) from = gaN;
    const uint16_t end = (gaN - from > GA_PAGE_ROWS) ? (uint16_t)(from + GA_PAGE_ROWS) : gaN;
    BoundedText out(GA_PAGE_FIXED + (end - from) * ST_PER_GA);
    if (out.failed())
    {
        res.sendOutOfMemory();
        return;
    }
    const bool gaCut = c->groupObjectsTruncated();
    out.addf(GA_PAGE, paText(_gaPa).c_str(), (unsigned)from, (unsigned)gaN, (unsigned long)gaVersion(ga, gaN, _gaPa, gaCut));
    for (uint16_t i = from; i < end; i++)
    {
        // "unk" per ROW: ga 0 means "no group address" unless this row's TSAP pointed past an address
        // table that stayed silent. A run-wide flag marked empty rows as unreadable.
        out.addf(ST_GA_ROW, i > from ? "," : "", (unsigned)ga[i].ga, (unsigned)ga[i].co, (unsigned)ga[i].flags,
                 (unsigned)ga[i].prio, (unsigned)ga[i].sizeCode, ga[i].cfgValid ? "true" : "false",
                 ga[i].gaUnknown ? "true" : "false");
    }
    out += "]}";
    if (out.cut())
    {
        logError("knxOTA", "ga rows exceed their bound (%u B)", (unsigned)out.size());
        res.sendOutOfMemory();
        return;
    }
    res.setContentType("application/json");
    int len = 0;
    uint8_t *body = out.take(len);
    res.sendOwned(body, len);
}

// ── Local file list: every drive walks with its own handle, the KNX-side listing keeps its cursor ──────
void FileTransferWebClient::handleFiles(WebRequest &req, WebResponse &res)
{
    const std::string fs = req.getQueryParam("fs");
    const std::string job = req.getQueryParam("job");
    const bool wantDelta = (job == "delta");
    BoundedText out(OPENKNX_FTC_WEB_FILES_BUF, 1024); // a smaller block when the heap has no large one: fewer files
    if (out.failed())
    {
        res.sendOutOfMemory();
        return;
    }
    out += "[";
    bool first = true;
    bool cut = false;
    // The tab decides what belongs in the list: .okd is a patch, everything else must at least look
    // like an image. The accepted endings are named on the page, so nothing vanishes without a word.
    auto endsWith = [](const char *name, const char *ext) {
        const size_t n = strlen(name), e = strlen(ext);
        return n > e && strcasecmp(name + n - e, ext) == 0;
    };
    auto add = [&](const char *name, uint32_t size) {
        if (cut) return;
        const bool okd = endsWith(name, ".okd");
        if (okd != wantDelta) return;
        if (!wantDelta && !(endsWith(name, ".bin") || endsWith(name, ".uf2") || endsWith(name, ".gz")))
            return;
        const size_t mark = out.size();
        if (!first) out += ",";
        out += "{\"name\":\"";
        addJsonEsc(out, name);
        char sz[24];
        fmtSize(sz, sizeof(sz), size);
        out.addf("\",\"size\":\"%s\",\"bytes\":%u}", sz, (unsigned)size);
        if (!out.cut() && out.room() >= 1) // the closing bracket still fits
        {
            first = false;
            return;
        }
        out.rollback(mark);
        cut = true;
    };
#if defined(OPENKNX_SDCARD) || defined(OPENKNX_EXTFLASH)
    // sd/efc: one pass with its own handle; the store cursor of a running FTC listing stays untouched, no snapshot on the heap
    struct Walk
    {
        decltype(add) *addFn;
        bool *cut;
        uint16_t seen;
    } w{&add, &cut, 0};
    bool (*cb)(void *, const char *, bool, uint64_t) = [](void *c, const char *n, bool isDir, uint64_t sz) -> bool {
        Walk *w = static_cast<Walk *>(c);
        if (++w->seen > 512) // the loop must not walk a huge directory in one pass
        {
            *w->cut = true;
            return false;
        }
        if (!isDir) (*w->addFn)(n, sz > 0xFFFFFFFFull ? 0xFFFFFFFFu : (uint32_t)sz);
        return !*w->cut; // the answer is full
    };
#endif
    if (fs == "sd")
    {
#ifdef OPENKNX_SDCARD
        sd::fileStore.forEach("/", cb, &w, &cut); // also cut: the card went away during the listing
#endif
    }
    else if (fs == "efc")
    {
#ifdef OPENKNX_EXTFLASH
        efc::fileStore.forEach("/", cb, &w);
#endif
    }
    else
    {
        File d = LittleFS.open("/", "r");
        for (File f = d.openNextFile(); f && !cut; f = d.openNextFile())
            if (!f.isDirectory()) add(f.name(), (uint32_t)f.size());
    }
    out += "]";
    res.setContentType("application/json");
    if (cut)
    {
        // no list entry for it: the page would offer it as a file
        res.setHeader("X-List-Cut", "1");
        logWarning("knxOTA", "file list cut at %u B", (unsigned)out.size());
    }
    int len = 0;
    uint8_t *body = out.take(len);
    res.sendOwned(body, len);
}


// ── Arming: hand the job to the client and answer at once ──────────────────────────────────────
void FileTransferWebClient::handleStart(WebRequest &req, WebResponse &res)
{
    auto *c = FileTransferClient::instance();
    if (c->isBusy())
    {
        res.setStatus(409);
        res.send("Es läuft bereits ein Auftrag");
        return;
    }
    const uint16_t pa = parsePa(req.getQueryParam("pa"));
    if (!pa)
    {
        res.setStatus(400);
        res.send("Physikalische Adresse nicht lesbar");
        return;
    }
    const std::string job = req.getQueryParam("job");
    const uint8_t mode = req.getQueryParam("mode") == "fast" ? 1 : 0;
    const uint16_t win = (uint16_t)atoi(req.getQueryParam("win").c_str()); // 0 = let it regulate

    if (job == "perf")
    {
        const uint32_t kb = (uint32_t)atoi(req.getQueryParam("kb").c_str());
        // The drive the measurement writes to is a real argument -- the dropdown must reach it.
        const std::string drive = req.getQueryParam("drive");
        if (mode == 1) _gaLost = true;
        c->requestPerf(pa, (kb ? kb : 50) * 1024, 0, mode, req.getQueryParam("keep") == "1", win,
                       drive.c_str());
    }
    else
    {
        std::string path = req.getQueryParam("path");
        const std::string fs = req.getQueryParam("fs");
        if (path.empty())
        {
            res.setStatus(400);
            res.send("Keine Datei gewählt");
            return;
        }
        if (fs == "sd") path = "sd/" + path;
        else if (fs == "efc") path = "efc/" + path;
        else if (path[0] != '/') path.insert(0, "/");
#ifdef OPENKNX_FTC_DELTA_UPDATE
        if (job == "delta")
        {
            c->requestDeltaSend(pa, path.c_str());
            if (!c->isBusy())
            {
                res.setStatus(409);
                res.send("Die Differenz wurde nicht angenommen — kein gültiger OKD1-Kopf?");
                return;
            }
            res.setContentType("text/plain");
            res.send("OK");
            return;
        }
#endif
        if (mode == 1) _gaLost = true; // the fast bitmap and the group-address table share their storage
        // Where it lands ON THE TARGET. Empty = the target's internal filesystem, which is the only
        // place a firmware can be applied from.
        const std::string dst = req.getQueryParam("dst");
        std::string remote;
        if (dst == "sd" || dst == "efc")
        {
            const size_t sl = path.find_last_of('/');
            remote = dst + "/" + (sl == std::string::npos ? path : path.substr(sl + 1));
        }
        c->requestUpload(pa, path.c_str(), 0, req.getQueryParam("resume") != "1", mode,
                         req.getQueryParam("apply") == "1", remote.c_str(), win);
    }
    // The client refuses some jobs without ever entering a state (source missing, drive gone, path too
    // long) -- it only logs. Answering OK there would make the page report a run that never began, and
    // its balance would carry the PREVIOUS operation's message.
    if (!c->isBusy())
    {
        res.setStatus(409);
        res.send("Der Auftrag wurde nicht angenommen — Quelle nicht lesbar? Siehe Protokoll des Geräts.");
        return;
    }
    res.setContentType("text/plain");
    res.send("OK");
}


void FileTransferWebClient::handleCancel(WebRequest &req, WebResponse &res)
{
    FileTransferClient::instance()->requestCancel();
    res.setContentType("text/plain");
    res.send("OK");
}


void FileTransferWebClient::handleTrigger(WebRequest &req, WebResponse &res)
{
    if (FileTransferClient::instance()->isBusy())
    {
        res.setStatus(409);
        res.send("Es läuft bereits ein Auftrag");
        return;
    }
    const uint16_t pa = parsePa(req.getQueryParam("pa"));
    std::string path = req.getQueryParam("path");
    if (!pa || path.empty())
    {
        res.setStatus(400);
        res.send("Adresse oder Datei fehlt");
        return;
    }
    if (path[0] != '/') path.insert(0, "/"); // the target always keeps it in its root
    FileTransferClient::instance()->requestFwUpdate(pa, path.c_str());
    res.setContentType("text/plain");
    res.send("OK");
}


#ifdef OPENKNX_FTC_SECURITY
// The password arrives in the BODY, never in the request line: a query parameter would travel through
// every proxy log on the way. It is used once and stored nowhere.
void FileTransferWebClient::handleAuth(WebRequest &req, WebResponse &res)
{
    if (FileTransferClient::instance()->isBusy())
    {
        res.setStatus(409);
        res.send("Es läuft bereits ein Auftrag");
        return;
    }
    const uint16_t pa = parsePa(req.getQueryParam("pa"));
    if (!pa)
    {
        res.setStatus(400);
        res.send("Physikalische Adresse nicht lesbar");
        return;
    }
    std::string pw;
    if (req.body() && req.bodyLength()) pw.assign((const char *)req.body(), req.bodyLength());
    _authPa = pa; // which target the outcome in the status belongs to
    if (pw.empty()) FileTransferClient::instance()->requestLogout(pa);
    else FileTransferClient::instance()->requestLogin(pa, pw.c_str());
    pw.assign(pw.size(), '\0'); // do not leave it in the heap block this string hands back
    res.setContentType("text/plain");
    // Armed, not done: the challenge-response is three bus round trips and the answer cannot be waited
    // for here without blocking the web server. The page reads the outcome from /knxota/status.
    res.send("armed");
}
#endif


// scan / led / feat -- one entry point, the path says which. Each arms one client operation, so a
// running job must block them: the client serves one at a time and a second request would end the first.
void FileTransferWebClient::handleAction(WebRequest &req, WebResponse &res)
{
    auto *c = FileTransferClient::instance();
    const std::string p = req.getUri();
    const uint16_t pa = parsePa(req.getQueryParam("pa"));
    if (c->isBusy())
    {
        res.setStatus(409);
        res.send("Es läuft bereits ein Auftrag");
        return;
    }
    if (p.find("/feat") != std::string::npos)
    {
        if (!pa)
        {
            res.setStatus(400);
            res.send("Physikalische Adresse nicht lesbar");
            return;
        }
        _featPa = pa; // the answer is only reported back while it still belongs to this PA
        c->requestDeviceInfo(pa);
    }
    else if (p.find("/scan") != std::string::npos)
    {
        // The range is the page's, not the target's: an installer often sweeps a line he is not on.
        const std::string as = req.getQueryParam("area"), ls = req.getQueryParam("line");
        const uint16_t own = knx.individualAddress();
        unsigned a = as.empty() ? ((own >> 12) & 0x0F) : (unsigned)atoi(as.c_str());
        unsigned l = ls.empty() ? ((own >> 8) & 0x0F) : (unsigned)atoi(ls.c_str());
        if (a > 15) a = 15;
        if (l > 15) l = 15;
        const bool area = req.getQueryParam("scope") == "area";
        const uint16_t start = area ? (uint16_t)((a << 12) | 0x0001) : (uint16_t)((a << 12) | (l << 8) | 0x01);
        const uint16_t end = area ? (uint16_t)((a << 12) | 0x0FFF) : (uint16_t)((a << 12) | (l << 8) | 0xFF);
        // Completeness is the promise of this sweep, not an option: a single pass loses answers to
        // multicast/coupler drops, so the page always asks for the deep scan (several passes -> union,
        // plus the ack-only addresses recorded after the last pass). The knobs only tune how deep.
        // kind=ets runs the connection-oriented sweep instead: one T_Connect per address, which reaches
        // BCU1/BCU2 devices that never answer a connectionless DeviceDescriptor_Read. It forces one pass.
        const bool co = req.getQueryParam("kind") == "ets";
        const std::string sws = req.getQueryParam("sweeps"), tmos = req.getQueryParam("tmo"),
                          paces = req.getQueryParam("pace");
        unsigned sw = sws.empty() ? 2u : (unsigned)atoi(sws.c_str());
        if (sw < 1) sw = 1;
        if (sw > 3) sw = 3;
        // 0 keeps the driver default; clamp the rest so a hand-typed value cannot stall the sweep.
        unsigned tmo = tmos.empty() ? 0u : (unsigned)atoi(tmos.c_str());
        if (tmo && tmo < 50) tmo = 50;
        if (tmo > 2000) tmo = 2000;
        unsigned pace = paces.empty() ? 0u : (unsigned)atoi(paces.c_str());
        if (pace > 1000) pace = 1000;
        _scanHits.clear();
        // info = true runs the FULL probe on every System B hit: it reads order number and version, which
        // is what lets the list name an OpenKNX device instead of only flagging it.
        c->requestScan(start, end, area ? "Bereich" : "Linie", (uint8_t)sw, co, true, true, nullptr,
                       pace, 0, tmo);
    }
    res.setContentType("text/plain");
    res.send("OK");
}


// One drive per call -- the client serves one command at a time, so the browser chains them.
void FileTransferWebClient::handleDrives(WebRequest &req, WebResponse &res)
{
    auto *c = FileTransferClient::instance();
    if (c->isBusy())
    {
        res.setStatus(409);
        res.send("Es läuft bereits ein Auftrag");
        return;
    }
    const uint16_t pa = parsePa(req.getQueryParam("pa"));
    if (!pa)
    {
        res.setStatus(400);
        res.send("Physikalische Adresse nicht lesbar");
        return;
    }
    const std::string fs = req.getQueryParam("fs");
    const int idx = (fs == "sd") ? 1 : (fs == "efc") ? 2 : 0;
    if (_drvPa != pa)
    {
        for (int i = 0; i < 3; i++) _drv[i] = DriveInfo();
        _drvPa = pa;
    }
    _dfPending = (int8_t)idx;
    c->requestFsInfo(pa, idx == 1 ? "sd/" : idx == 2 ? "efc/" : "");
    res.setContentType("text/plain");
    res.send("OK");
}


// The group-address table is its own bus run of minutes -- never folded into "Gerät lesen".
void FileTransferWebClient::handleGa(WebRequest &req, WebResponse &res)
{
    auto *c = FileTransferClient::instance();
    if (c->isBusy())
    {
        res.setStatus(409);
        res.send("Es läuft bereits ein Auftrag");
        return;
    }
    const uint16_t pa = parsePa(req.getQueryParam("pa"));
    if (!pa)
    {
        res.setStatus(400);
        res.send("Physikalische Adresse nicht lesbar");
        return;
    }
    _gaPa = pa;
    _gaLost = false;
    c->requestGroupComm(pa);
    res.setContentType("text/plain");
    res.send("OK");
}


// The target's programming mode (PID 54). One write, no answer -- the state is read back with the device.
void FileTransferWebClient::handleProgMode(WebRequest &req, WebResponse &res)
{
    auto *c = FileTransferClient::instance();
    const uint16_t pa = parsePa(req.getQueryParam("pa"));
    if (!pa)
    {
        res.setStatus(400);
        res.send("Physikalische Adresse nicht lesbar");
        return;
    }
    c->requestLed(pa, req.getQueryParam("on") == "1" ? 1 : 0);
    res.setContentType("text/plain");
    res.send("OK");
}


void FileTransferWebClient::setup()
{
    openknxNetwork.webserver.addMenuItem("knxOTA", "/knxota", 20);
    openknxNetwork.webserver.addRoute(WEB_GET, "/assets/knxota.css",
                                      Webserver::Asset(WebAssets::knxota_css_mime, WebAssets::knxota_css_gz,
                                                       sizeof(WebAssets::knxota_css_gz)));
    openknxNetwork.webserver.addRoute(WEB_GET, "/assets/knxota.js",
                                      Webserver::Asset(WebAssets::knxota_js_mime, WebAssets::knxota_js_gz,
                                                       sizeof(WebAssets::knxota_js_gz)));
    openknxNetwork.webserver.addStylesheet("/assets/knxota.css");
    openknxNetwork.webserver.addJavaScript("/assets/knxota.js");

    openknxNetwork.webserver.addRoute(WEB_GET, "/knxota", [this](WebRequest &q, WebResponse &r) { handlePage(q, r); });
    // the routes below touch the client state: their handlers run in the loop task (ESP32: not in httpd)
    openknxNetwork.webserver.addLoopRoute(WEB_GET, "/knxota/status", [this](WebRequest &q, WebResponse &r) { handleStatus(q, r); });
    openknxNetwork.webserver.addLoopRoute(WEB_GET, "/knxota/files", [this](WebRequest &q, WebResponse &r) { handleFiles(q, r); });
    openknxNetwork.webserver.addLoopRoute(WEB_GET, "/knxota/garows", [this](WebRequest &q, WebResponse &r) { handleGaRows(q, r); });
    openknxNetwork.webserver.addLoopRoute(WEB_POST, "/knxota/start", [this](WebRequest &q, WebResponse &r) { handleStart(q, r); });
    openknxNetwork.webserver.addLoopRoute(WEB_POST, "/knxota/cancel", [this](WebRequest &q, WebResponse &r) { handleCancel(q, r); });
    openknxNetwork.webserver.addLoopRoute(WEB_POST, "/knxota/trigger", [this](WebRequest &q, WebResponse &r) { handleTrigger(q, r); });
#ifdef OPENKNX_FTC_SECURITY
    openknxNetwork.webserver.addLoopRoute(WEB_POST, "/knxota/auth", [this](WebRequest &q, WebResponse &r) { handleAuth(q, r); });
#endif
    openknxNetwork.webserver.addLoopRoute(WEB_POST, "/knxota/scan", [this](WebRequest &q, WebResponse &r) { handleAction(q, r); });
    openknxNetwork.webserver.addLoopRoute(WEB_POST, "/knxota/feat", [this](WebRequest &q, WebResponse &r) { handleAction(q, r); });
    openknxNetwork.webserver.addLoopRoute(WEB_POST, "/knxota/ga", [this](WebRequest &q, WebResponse &r) { handleGa(q, r); });
    openknxNetwork.webserver.addLoopRoute(WEB_POST, "/knxota/drives", [this](WebRequest &q, WebResponse &r) { handleDrives(q, r); });
    openknxNetwork.webserver.addLoopRoute(WEB_POST, "/knxota/progmode", [this](WebRequest &q, WebResponse &r) { handleProgMode(q, r); });
}
#endif

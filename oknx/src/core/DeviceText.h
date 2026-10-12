// ─────────────────────────────────────────────────────────────────────────────
//   Open ■
//   ┬────┴   OpenKNX · ftc — descriptive Device Object Properties over the bus
//   ■ KNX    Erkan Çolak · GPL-3.0
// ─────────────────────────────────────────────────────────────────────────────
//
// The FTC device steckbrief reads a fixed set of PIDs inside the shared FileTransferClient. The
// descriptive Properties (03_05_01 4.2.2 / 4.2.19 / 4.3.6) are read here instead, straight over the
// host's own KNXnet/IP tunnel, so the device firmware pays no RAM for them.
//
// Two rules of the Property services shape this file:
//   - start index 0 answers the CURRENT number of elements, as two octets (03_03_07 3.4.4.1)
//   - the element count of A_PropertyValue_Read is a 4 bit field, so a text with one octet per
//     element arrives in blocks of at most 15

#pragma once

#include <cstdint>
#include <cstring>
#include <string>

#include "Access.h"          // ftc::AccessDeps + the property-callback idiom
#include "../knx_ip_tunnel.h"

namespace ftc
{

namespace detail
{

inline volatile bool g_dtSeen = false;
inline uint16_t g_dtPa = 0;
inline uint8_t g_dtPid = 0;
inline uint8_t g_dtData[64] = {0};
inline uint8_t g_dtLen = 0;

inline void dtAnswer(uint16_t pa, uint8_t objectIndex, uint8_t propertyId, const uint8_t* data, uint8_t length)
{
    if (pa != g_dtPa || objectIndex != 0 || propertyId != g_dtPid) return;

    g_dtLen = (length > sizeof(g_dtData)) ? (uint8_t)sizeof(g_dtData) : length;
    if (g_dtLen && data) std::memcpy(g_dtData, data, g_dtLen);
    g_dtSeen = true;
}

/**
 * @brief One A_PropertyValue_Read on object index 0; returns the octets answered, 0 on timeout or refusal.
 * @details A device that refuses answers with zero elements and no data, which arrives here as length 0.
 */
inline uint8_t readOnce(KnxIpTunnel& tunnel, uint16_t pa, uint8_t pid, uint16_t startIndex, uint8_t count,
                        uint8_t* out, size_t cap, const AccessDeps& d, uint32_t timeoutMs)
{
    g_dtSeen = false;
    g_dtLen = 0;
    g_dtPa = pa;
    g_dtPid = pid;

    const FtcPropCb prev = tunnel.propertyCallback();
    tunnel.setPropertyCallback(&dtAnswer);

    if (!tunnel.sendPropertyValueRead(pa, 0, pid, count, startIndex))
    {
        tunnel.setPropertyCallback(prev);
        return 0;
    }

    const uint64_t until = d.nowMs() + timeoutMs;
    while (!g_dtSeen && d.nowMs() < until && !(d.aborted && d.aborted()))
        d.pump();

    tunnel.setPropertyCallback(prev);
    if (!g_dtSeen || g_dtLen == 0) return 0;

    const uint8_t take = (g_dtLen > cap) ? (uint8_t)cap : g_dtLen;
    std::memcpy(out, g_dtData, take);
    return take;
}

} // namespace detail

/**
 * @brief Read a fixed-size Property of a bus device. Returns the octets read, 0 if it is absent.
 */
inline size_t readBusProperty(KnxIpTunnel& tunnel, uint16_t pa, uint8_t pid, uint8_t* out, size_t cap,
                              const AccessDeps& d, uint32_t timeoutMs = 1500)
{
    return detail::readOnce(tunnel, pa, pid, 1, 1, out, cap, d, timeoutMs);
}

/**
 * @brief Read a text Property (one ISO 8859-1 octet per element) of a bus device into `out`.
 * @details Asks index 0 for the length first, then fetches in blocks of 15 - the largest a classic
 *          A_PropertyValue_Read can carry. Returns the number of characters, 0 if the Property is absent.
 *          `out` is always NUL terminated. The octets stay ISO 8859-1; use latin1ToUtf8() to display them.
 */
inline size_t readBusText(KnxIpTunnel& tunnel, uint16_t pa, uint8_t pid, char* out, size_t cap,
                          const AccessDeps& d, uint32_t timeoutMs = 1500)
{
    if (cap == 0) return 0;
    out[0] = 0;

    uint8_t lenBuf[4] = {0};
    if (detail::readOnce(tunnel, pa, pid, 0, 1, lenBuf, sizeof(lenBuf), d, timeoutMs) < 2) return 0;

    uint16_t elements = (uint16_t)((lenBuf[0] << 8) | lenBuf[1]);
    if (elements == 0) return 0;
    if (elements > cap - 1) elements = (uint16_t)(cap - 1);

    size_t got = 0;
    uint16_t index = 1;
    while (got < elements)
    {
        const uint16_t left = (uint16_t)(elements - got);
        const uint8_t block = (uint8_t)(left > 15 ? 15 : left);
        const uint8_t n = detail::readOnce(tunnel, pa, pid, index, block, (uint8_t*)out + got, cap - 1 - got,
                                           d, timeoutMs);
        if (n == 0) break; // a device that stops answering leaves the part already read

        got += n;
        index = (uint16_t)(index + n);
    }

    out[got] = 0;
    return got;
}

/**
 * @brief The descriptive Properties of one bus device, as far as it carries them.
 */
struct BusDeviceText
{
    char name[81] = {0};      ///< PID_OBJECT_NAME (2)
    char hardwareId[41] = {0}; ///< PID_MANUFACTURER_DATA (19)
    char firmwareName[49] = {0}; ///< manufacturer specific PID 203
    char mfrDeviceName[81] = {0}; ///< manufacturer specific PID 204
    char firmwareBuild[17] = {0}; ///< manufacturer specific PID 206, short git hash
    char mcu[17] = {0};           ///< manufacturer specific PID 207, chip the firmware is built for
    uint32_t buildTimestamp = 0;  ///< PID 205, seconds since the epoch
    uint8_t productId[10] = {0}; bool haveProductId = false; ///< PID_PRODUCT_ID (55)
    uint16_t manufacturer = 0; bool haveManufacturer = false; ///< PID_MANUFACTURER_ID (12)
    uint16_t mask = 0; bool haveMask = false;                 ///< PID_DEVICE_DESCRIPTOR (83)
    uint8_t orderInfo[10] = {0}; bool haveOrderInfo = false;  ///< PID_ORDER_INFO (15)
    uint8_t peiType = 0; bool havePeiType = false;           ///< PID_PEI_TYPE (16)
    uint8_t maxRetry = 0; bool haveMaxRetry = false;         ///< PID_MAX_RETRY_COUNT (52)

    bool any() const
    {
        return name[0] || hardwareId[0] || firmwareName[0] || mfrDeviceName[0] || firmwareBuild[0] ||
               mcu[0] || buildTimestamp || haveProductId || havePeiType || haveMaxRetry || haveManufacturer ||
               haveMask || haveOrderInfo;
    }
};

/**
 * @brief Read every descriptive Property a device may carry. Absent ones simply stay empty.
 */
inline BusDeviceText readBusDeviceText(KnxIpTunnel& tunnel, uint16_t pa, const AccessDeps& d,
                                       uint32_t timeoutMs = 1500)
{
    BusDeviceText t;
    readBusText(tunnel, pa, 2, t.name, sizeof(t.name), d, timeoutMs);
    readBusText(tunnel, pa, 19, t.hardwareId, sizeof(t.hardwareId), d, timeoutMs);

    uint8_t buf[16] = {0};

    if (readBusProperty(tunnel, pa, 12, buf, sizeof(buf), d, timeoutMs) >= 2)
    {
        t.manufacturer = (uint16_t)((buf[0] << 8) | buf[1]);
        t.haveManufacturer = true;
    }
    if (readBusProperty(tunnel, pa, 83, buf, sizeof(buf), d, timeoutMs) >= 2)
    {
        t.mask = (uint16_t)((buf[0] << 8) | buf[1]);
        t.haveMask = true;
    }
    if (readBusProperty(tunnel, pa, 15, buf, sizeof(buf), d, timeoutMs) >= sizeof(t.orderInfo))
    {
        std::memcpy(t.orderInfo, buf, sizeof(t.orderInfo));
        t.haveOrderInfo = true;
    }

    // PIDs above 201 are manufacturer specific (03_05_01 4.3.1) and only mean what OpenKNX says they
    // mean on an OpenKNX device. Two Siemens devices answer 203 and 204 with unrelated data, so read
    // them only after PID_MANUFACTURER_ID confirms who is answering.
    if (t.haveManufacturer && t.manufacturer == 0x00FA)
    {
        readBusText(tunnel, pa, 203, t.firmwareName, sizeof(t.firmwareName), d, timeoutMs);
        readBusText(tunnel, pa, 204, t.mfrDeviceName, sizeof(t.mfrDeviceName), d, timeoutMs);
        readBusText(tunnel, pa, 206, t.firmwareBuild, sizeof(t.firmwareBuild), d, timeoutMs);
        readBusText(tunnel, pa, 207, t.mcu, sizeof(t.mcu), d, timeoutMs);
        if (readBusProperty(tunnel, pa, 205, buf, sizeof(buf), d, timeoutMs) >= 4)
            t.buildTimestamp = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) | ((uint32_t)buf[2] << 8) | buf[3];
    }

    if (readBusProperty(tunnel, pa, 55, buf, sizeof(buf), d, timeoutMs) >= sizeof(t.productId))
    {
        std::memcpy(t.productId, buf, sizeof(t.productId));
        t.haveProductId = true;
    }
    if (readBusProperty(tunnel, pa, 16, buf, sizeof(buf), d, timeoutMs) >= 1)
    {
        t.peiType = buf[0];
        t.havePeiType = true;
    }
    if (readBusProperty(tunnel, pa, 52, buf, sizeof(buf), d, timeoutMs) >= 1)
    {
        t.maxRetry = buf[0];
        t.haveMaxRetry = true;
    }
    return t;
}

} // namespace ftc

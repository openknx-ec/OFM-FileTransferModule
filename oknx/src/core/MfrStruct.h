// ─────────────────────────────────────────────────────────────────────────────
//   Open ■
//   ┬────┴   OpenKNX · oknx — owner check of the manufacturer specific Device Object Properties
//   ■ KNX    Erkan Çolak · GPL-3.0
// ─────────────────────────────────────────────────────────────────────────────
//
// Properties in the Device Object above 201 are manufacturer specific (03_05_01 4.3.1), and other
// manufacturers answer them with their own data. An OpenKNX device names itself in PID 202, so 203 ff.
// are read only when PID 202 carries "OpenKNX" and marks the PID as present.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace ftc
{

/**
 * @brief PID 202 of an OpenKNX device: "OpenKNX", layout version, one bit per present PID (bit n = PID 202 + n).
 */
struct MfrStructInfo
{
    bool valid = false;
    uint8_t version = 0;
    uint8_t present = 0;

    /** @brief True when this device marks pid as an OpenKNX Property. */
    bool has(uint8_t pid) const
    {
        return valid && pid >= 202 && pid <= 209 && ((present >> (pid - 202)) & 1) != 0;
    }
};

/** @brief Parse the 9 octets of PID 202; anything shorter or without "OpenKNX" is not an OpenKNX device. */
inline MfrStructInfo parseMfrStructInfo(const uint8_t* data, size_t length)
{
    MfrStructInfo info;
    if (length >= 9 && std::memcmp(data, "OpenKNX", 7) == 0)
    {
        info.valid = true;
        info.version = data[7];
        info.present = data[8];
    }
    return info;
}

} // namespace ftc

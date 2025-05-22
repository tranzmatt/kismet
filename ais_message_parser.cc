// Copyright (c) 2023, Kismet Wireless, All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//     * Neither the name of Kismet Wireless nor the names of its
//       contributors may be used to endorse or promote products derived from
//       this software without specific prior written permission//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#include "ais_message_parser.h"
#include "util.h" // For trim functions if needed, though string methods are used here
#include <stdexcept>
#include <algorithm>
#include <cmath> // For round, pow
#include <fmt/format.h> // For ETA string formatting

namespace AISParser {

AISMessage::AISMessage(const std::string& encoded_payload, int num_fill_bits) : message_type(0) {
    for (char c : encoded_payload) {
        int val = static_cast<unsigned char>(c);
        val -= 48;
        if (val > 40) {
            val -= 8;
        }

        if (val < 0 || val > 63) {
            // Consider throwing an error or logging for invalid characters
            // For now, skip invalid characters or treat as 0?
            // Let's assume valid input as per NMEA spec for now.
            // If strict error handling is needed, this is a place to add it.
            // For robustness, could throw std::runtime_error here.
        }

        for (int i = 5; i >= 0; --i) {
            payload_bits.push_back((val >> i) & 1);
        }
    }

    if (num_fill_bits > 0 && num_fill_bits < 6 && payload_bits.size() >= static_cast<size_t>(num_fill_bits)) {
        for (int i = 0; i < num_fill_bits; ++i) {
            payload_bits.pop_back();
        }
    }

    if (payload_bits.size() >= 6) {
        message_type = static_cast<int>(get_uint(0, 6));
    } else {
        // Not enough bits for a message type, should ideally throw or log
        message_type = -1; // Indicate error or unknown
    }
}

uint64_t AISMessage::get_uint(size_t start_bit, size_t num_bits) const {
    if (start_bit + num_bits > payload_bits.size() || num_bits > 64) {
        // throw std::out_of_range("AISMessage::get_uint: Bit range out of bounds or too large.");
        // Kismet convention is often to log and return 0/default
        _MSG_ERROR_PACKET("AISMessage::get_uint: Bit range out of bounds (start {}, num {}, total {}) or too large (num_bits {} > 64).",
            start_bit, num_bits, payload_bits.size(), num_bits);
        return 0;
    }

    uint64_t val = 0;
    for (size_t i = 0; i < num_bits; ++i) {
        val <<= 1;
        if (payload_bits[start_bit + i]) {
            val |= 1;
        }
    }
    return val;
}

int64_t AISMessage::get_int(size_t start_bit, size_t num_bits) const {
    if (start_bit + num_bits > payload_bits.size() || num_bits > 64) {
        // throw std::out_of_range("AISMessage::get_int: Bit range out of bounds or too large.");
        _MSG_ERROR_PACKET("AISMessage::get_int: Bit range out of bounds (start {}, num {}, total {}) or too large (num_bits {} > 64).",
            start_bit, num_bits, payload_bits.size(), num_bits);
        return 0;
    }
    if (num_bits == 0) return 0;


    uint64_t u_val = get_uint(start_bit, num_bits);

    // Check if MSB is set (sign bit)
    if (num_bits > 0 && (u_val & (1ULL << (num_bits - 1)))) {
        // Negative number, perform two's complement
        // Extend the sign bit to 64 bits, then invert and add 1
        // A simpler way for fixed bit width: if negative, it's u_val - (1 << num_bits)
        return static_cast<int64_t>(u_val) - (1ULL << num_bits);
    }
    return static_cast<int64_t>(u_val);
}

std::string AISMessage::get_string(size_t start_bit, size_t num_chars) const {
    if (start_bit + (num_chars * 6) > payload_bits.size()) {
        // throw std::out_of_range("AISMessage::get_string: Bit range out of bounds.");
        _MSG_ERROR_PACKET("AISMessage::get_string: Bit range out of bounds (start {}, num_chars {}, total_bits {}).",
            start_bit, num_chars, payload_bits.size());
        return "";
    }

    std::string s;
    s.reserve(num_chars);

    for (size_t i = 0; i < num_chars; ++i) {
        uint8_t char_val = static_cast<uint8_t>(get_uint(start_bit + (i * 6), 6));
        if (char_val < 32) { // 0-31 range
            s += static_cast<char>(char_val + 64); // Maps to '@' through '_'
        } else { // 32-63 range
            s += static_cast<char>(char_val); // Maps to ' ' through '?'
        }
    }

    // Trim trailing '@' characters and then spaces
    size_t last_char = s.find_last_not_of('@');
    if (last_char != std::string::npos) {
        s.erase(last_char + 1);
    } else { // String was all '@'s
        s.clear();
    }
    
    // Trim trailing spaces
    last_char = s.find_last_not_of(' ');
    if (last_char != std::string::npos) {
        s.erase(last_char + 1);
    } else if (!s.empty() && s[0] == ' ') { // String was all spaces (and not empty from @ trim)
        s.clear();
    }


    return s;
}

// AISMessageType123 (Position Report Class A)
AISMessageType123::AISMessageType123(const std::string& encoded_payload, int num_fill_bits)
    : AISMessage(encoded_payload, num_fill_bits) {}

void AISMessageType123::parse(nlohmann::json& out_json) const {
    out_json["message_type"] = message_type;
    out_json["repeat_indicator"] = get_uint(6, 2);
    out_json["mmsi"] = get_uint(8, 30);
    out_json["nav_status"] = get_uint(38, 4);
    out_json["rot"] = get_int(42, 8); // Rate of Turn: -128 to 127. -128 means not available.
                                     // Values from -127 to 127 represent turns of 0 to > 5 deg/30s
                                     // We store raw value; interpretation can be done by UI or later processing.
    out_json["sog"] = get_uint(50, 10) / 10.0; // Speed Over Ground in 0.1 knot steps
    out_json["pos_accuracy"] = get_uint(60, 1); // 0 = low (<10m), 1 = high (>10m)
    
    double lon = get_int(61, 28) / 600000.0; // Longitude in 1/10000 minutes
    double lat = get_int(89, 27) / 600000.0; // Latitude in 1/10000 minutes
    out_json["lon"] = lon;
    out_json["lat"] = lat;

    out_json["cog"] = get_uint(116, 12) / 10.0; // Course Over Ground in 0.1 degree steps
    out_json["true_heading"] = get_uint(128, 9); // 0-359 degrees, 511 = not available
    out_json["timestamp"] = get_uint(137, 6); // Second of UTC timestamp, 60=N/A, 61=manual, 62=dead recon, 63=inoperative
    out_json["maneuver_indicator"] = get_uint(143, 2); // 0=N/A, 1=No special, 2=Special
    // Spare: 3 bits (145-147)
    out_json["raim_flag"] = get_uint(148, 1); // RAIM flag: 0=not in use, 1=in use
    out_json["radio_status"] = get_uint(149, 19); // Communication state for SOTDMA, ITDMA etc.

    // Fields specific to message types 2 and 3 (Class A position report, assigned schedule / response to interrogation)
    // are often extensions or slight variations of type 1. For now, this general parser handles common fields.
    // A more detailed spec would show which fields are only for type 2 or 3.
}

// AISMessageType5 (Static and Voyage Related Data)
AISMessageType5::AISMessageType5(const std::string& encoded_payload, int num_fill_bits)
    : AISMessage(encoded_payload, num_fill_bits) {}

void AISMessageType5::parse(nlohmann::json& out_json) const {
    out_json["message_type"] = message_type;
    out_json["repeat_indicator"] = get_uint(6, 2);
    out_json["mmsi"] = get_uint(8, 30);
    out_json["ais_version"] = get_uint(38, 2); // 0=ITU1371, 1-3 future
    out_json["imo_number"] = get_uint(40, 30); // 0 = not available
    out_json["callsign"] = get_string(70, 7); // 7x 6-bit chars
    out_json["vessel_name"] = get_string(112, 20); // 20x 6-bit chars
    out_json["ship_type"] = get_uint(232, 8); // Type of ship and cargo
    out_json["dim_to_bow"] = get_uint(240, 9); // Dimension to Bow (meters)
    out_json["dim_to_stern"] = get_uint(249, 9); // Dimension to Stern (meters)
    out_json["dim_to_port"] = get_uint(258, 6); // Dimension to Port (meters)
    out_json["dim_to_starboard"] = get_uint(264, 6); // Dimension to Starboard (meters)
    out_json["epfd_fix_type"] = get_uint(270, 4); // Type of EPFD (Electronic Position Fixing Device)
    
    uint32_t eta_month = get_uint(274, 4); // 0=N/A, 1-12
    uint32_t eta_day = get_uint(278, 5);   // 0=N/A, 1-31
    uint32_t eta_hour = get_uint(283, 5);  // 0-23, 24=N/A
    uint32_t eta_minute = get_uint(288, 6);// 0-59, 60=N/A

    // Format ETA string if values are valid
    if (eta_month >= 1 && eta_month <= 12 &&
        eta_day >= 1 && eta_day <= 31 &&
        eta_hour <= 23 && eta_minute <= 59) {
        out_json["eta_str"] = fmt::format("{:02}-{:02} {:02}:{:02} UTC", eta_month, eta_day, eta_hour, eta_minute);
    } else {
        out_json["eta_str"] = "N/A";
    }
    // Also store raw ETA components
    out_json["eta_month"] = eta_month;
    out_json["eta_day"] = eta_day;
    out_json["eta_hour"] = eta_hour;
    out_json["eta_minute"] = eta_minute;

    out_json["draught"] = get_uint(294, 8) / 10.0; // Draught in 0.1 meter steps
    out_json["destination"] = get_string(302, 20); // 20x 6-bit chars
    out_json["dte"] = get_uint(422,1); // Data Terminal Equipment ready flag (0=available, 1=not available/busy)
    // Spare bit at end
}

// static
int AISMessage::decode_6bit_ascii(char c) {
    int val = static_cast<unsigned char>(c);
    // Valid character range for AIS 6-bit encoding is ASCII 48-87 and 96-119.
    // ASCII 48-87 ('0' to 'W') map to values 0-39.
    // ASCII 96-119 ('`' to 'w') map to values 40-63.
    if (val < 48 || (val > 87 && val < 96) || val > 119) {
        _MSG_ERROR_PACKET("AIS: Invalid character '{}' (ASCII {}) for 6-bit decoding.", c, val);
        return -1; // Invalid character
    }

    val -= 48; // Shift '0'-'W' to 0-39
    if (val >= 40) { // Originally '`'-'w', which are ASCII 96-119. After -48, they are 48-71.
        val -= 8;    // Shift these to 40-63.
    }
    // Final check, though previous logic should ensure this.
    if (val < 0 || val > 63) {
         _MSG_ERROR_PACKET("AIS: Decoding logic error for char '{}', resulted in val {}.", c, val);
        return -1;
    }
    return val;
}

// Factory Function
std::unique_ptr<AISMessage> create_ais_message(int message_type, const std::string& encoded_payload, int num_fill_bits) {
    switch (message_type) {
        case 1:
        case 2:
        case 3:
            return std::make_unique<AISMessageType123>(encoded_payload, num_fill_bits);
        case 5:
            return std::make_unique<AISMessageType5>(encoded_payload, num_fill_bits);
        // Add other message types here as they are implemented
        // case 4: return std::make_unique<AISMessageType4>(...);
        // case 18: return std::make_unique<AISMessageType18>(...);
        // case 19: return std::make_unique<AISMessageType19>(...);
        // case 24: return std::make_unique<AISMessageType24>(...);
        default:
            _MSG_DEBUG("AIS: Unknown or unsupported message type: {}", message_type);
            return nullptr;
    }
}

} // namespace AISParser

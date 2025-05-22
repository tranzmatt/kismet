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
//       this software without specific prior written permission.
//
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

#include "phy_ais.h"

#include "globalregistry.h"
#include "kis_gps_packinfo.h"
#include "manuf.h"
#include "util.h"
#include "packet_metablob.h"
#include "kis_common_info.h"
#include "kis_protocols.h" // For packet_basic_data and kis_checksum_nmea_valid
#include "ais_message_parser.h" // For AISParser namespace

#include <nlohmann/json.hpp>
#include <fmt/format.h>
#include <string_view> // For string manipulation in parse_aivdm

kis_ais_phy::kis_ais_phy(int in_phyid) :
    kis_phy_handler(in_phyid) {

    packetchain_obj_ = Globalreg::globalreg->packetchain;
    entrytracker_obj_ = Globalreg::globalreg->entrytracker;
    devicetracker_obj_ = Globalreg::globalreg->devicetracker;

    set_phy_name("AIS");
    set_phy_description("AIS (Automatic Identification System) PHY");

    // Register packet components
    pack_comp_common = packetchain_obj_->register_component("COMMON", "Common packet data");
    pack_comp_json = packetchain_obj_->register_component("JSON", "JSON packet data");
    pack_comp_meta = packetchain_obj_->register_component("METABLOB", "Packet metadata blob");
    pack_comp_gps = packetchain_obj_->register_component("GPS", "GPS data");
    pack_comp_kisdatasrc = packetchain_obj_->register_component("KISDATASRC", "Kismet Datasource Info");

    // Register tracker fields
    ais_device_id = entrytracker_obj_->register_field("ais.device", "AIS Device Info",
        tracker_element_factory<ais_tracked_ais>());
    mmsi_id = entrytracker_obj_->register_field("ais.mmsi", "AIS MMSI",
        tracker_element_factory<tracker_element_string>());
    vessel_name_id = entrytracker_obj_->register_field("ais.common.name", "AIS Vessel Name",
        tracker_element_factory<tracker_element_string>());
    callsign_id = entrytracker_obj_->register_field("ais.common.callsign", "AIS Callsign",
        tracker_element_factory<tracker_element_string>());
    imo_id = entrytracker_obj_->register_field("ais.imo_number", "AIS IMO Number",
        tracker_element_factory<tracker_element_uint>());
    ship_type_id = entrytracker_obj_->register_field("ais.shiptype", "AIS Ship Type",
        tracker_element_factory<tracker_element_uint>()); // Could be string if we map types to names
    nav_status_id = entrytracker_obj_->register_field("ais.navstatus", "AIS Navigational Status",
        tracker_element_factory<tracker_element_uint>()); // Could be string
    destination_id = entrytracker_obj_->register_field("ais.destination", "AIS Destination",
        tracker_element_factory<tracker_element_string>());
    eta_id = entrytracker_obj_->register_field("ais.eta", "AIS ETA",
        tracker_element_factory<tracker_element_string>()); // Could be timestamp

    ais_manuf = Globalreg::globalreg->manufdb->make_manuf("AIS");

    packetchain_obj_->register_handler(&packet_handler, this, CHAINPOS_CLASSIFIER, -90);

    _MSG_INFO("AIS PHY created");
}

kis_ais_phy::~kis_ais_phy() {
    if (packetchain_obj_ != nullptr) {
        packetchain_obj_->remove_handler(&packet_handler, CHAINPOS_CLASSIFIER);
    }
    _MSG_INFO("AIS PHY destroyed");
}

mac_addr kis_ais_phy::mmsi_to_mac(const std::string& mmsi) {
    if (mmsi.length() != 9) {
        _MSG_ERROR("Invalid MMSI length for MAC conversion: {}", mmsi);
        return mac_addr(); // Return zero MAC
    }

    uint32_t mmsi_val = 0;
    try {
        mmsi_val = std::stoul(mmsi);
    } catch (const std::invalid_argument& ia) {
        _MSG_ERROR("Invalid MMSI string for MAC conversion (not numeric): {}", mmsi);
        return mac_addr();
    } catch (const std::out_of_range& oor) {
        _MSG_ERROR("Invalid MMSI string for MAC conversion (out of range): {}", mmsi);
        return mac_addr();
    }

    unsigned char bytes[6];
    bytes[0] = 0x02; // Locally administered
    bytes[1] = 0x41; // 'A'
    bytes[2] = 0x49; // 'I'
    // Use lower 3 bytes of MMSI for the remaining MAC bytes
    // This is just one way, ensuring it's unique enough for Kismet's purposes
    // MMSI is up to 30 bits, so fits in uint32_t.
    // MAC is 48 bits. OUI 02:41:49 (AIS) + lower 3 bytes of MMSI
    bytes[3] = (mmsi_val >> 16) & 0xFF; // Use middle part of MMSI for more variability if first digits are similar
    bytes[4] = (mmsi_val >> 8) & 0xFF;
    bytes[5] = mmsi_val & 0xFF;

    return mac_addr(bytes);
}

int kis_ais_phy::packet_handler(CHAINCALL_PARMS) {
    kis_ais_phy* ais_phy = static_cast<kis_ais_phy*>(auxdata);

    if (in_pack->error || in_pack->filtered || in_pack->duplicate) {
        return 0;
    }

    auto json_info = in_pack->fetch<kis_json_packinfo>(ais_phy->pack_comp_json);

    if (json_info == nullptr || (json_info->type != "ais" && json_info->type != "AIVDM")) {
        // _MSG_DEBUG("Packet is not AIS JSON or of type 'ais'/'AIVDM', type: {}", json_info ? json_info->type : "N/A");
        return 0;
    }

    nlohmann::json json_data;
    try {
        json_data = nlohmann::json::parse(json_info->json_string);
    } catch (const nlohmann::json::parse_error& e) {
        _MSG_ERROR("Failed to parse AIS JSON: {}", e.what());
        return 0;
    }

    // Add raw JSON to metablob for logging
    auto adata = in_pack->fetch_or_add<packet_metablob>(ais_phy->pack_comp_meta);
    adata->set_data("AIS_JSON", json_info->json_string);

    // The process_ais_json method will handle the rest, including AIVDM parsing
    if (!ais_phy->process_ais_json(json_data, in_pack)) {
        // Error already logged in process_ais_json or parse_aivdm
        return 0;
    }

    return 1; // Processed successfully
}

bool kis_ais_phy::process_ais_json(nlohmann::json& json_data, const std::shared_ptr<kis_packet>& packet) {
    std::string raw_aivdm_sentence;

    // Try to get the raw AIVDM sentence. It might be under different keys depending on the source.
    // Common keys are "raw", "line", "sentence", "aivdm_raw_sentence"
    if (json_data.contains("raw_sentence") && json_data["raw_sentence"].is_string()) {
        raw_aivdm_sentence = json_data["raw_sentence"].get<std::string>();
    } else if (json_data.contains("raw") && json_data["raw"].is_string()) {
        raw_aivdm_sentence = json_data["raw"].get<std::string>();
    } else if (json_data.contains("line") && json_data["line"].is_string()) {
        raw_aivdm_sentence = json_data["line"].get<std::string>();
    } else if (json_data.contains("sentence") && json_data["sentence"].is_string()) {
        raw_aivdm_sentence = json_data["sentence"].get<std::string>();
    } else {
        _MSG_DEBUG("AIS JSON does not contain a recognized raw AIVDM sentence field.");
        // We might have already parsed fields if the source pre-parses AIVDM
        // For now, we require the raw sentence for our own parsing logic.
        // In the future, could adapt to use pre-parsed fields if raw is missing.
        // For now, if no raw AIVDM sentence, we expect the datasource to have parsed it
        // and provided the necessary fields (like mmsi, lat, lon, etc.) directly in json_data.
        if (raw_aivdm_sentence.empty() && !json_data.contains("mmsi")) {
             _MSG_DEBUG("AIS JSON lacks raw sentence and pre-parsed MMSI. Cannot process.");
            return false;
        }
    }

    nlohmann::json parsed_ais_fields; // This will hold results from parse_aivdm or be json_data
    if (!raw_aivdm_sentence.empty()) {
        if (!parse_aivdm(raw_aivdm_sentence, parsed_ais_fields)) {
            // Error already logged in parse_aivdm if it's checksum or basic format
            // Or parse_aivdm might log specific parsing issues.
            _MSG_DEBUG("Failed to parse AIVDM sentence: {}", raw_aivdm_sentence);
            return false;
        }
    } else {
        // If no raw sentence, assume json_data itself contains the parsed fields
        // This allows datasources to provide already-parsed AIS data
        _MSG_DEBUG("No raw AIVDM sentence found, using provided JSON as parsed data.");
        parsed_ais_fields = json_data; // Use the input JSON directly
    }

    // MMSI Extraction
    std::string mmsi_str;
    if (parsed_ais_fields.count("mmsi") && parsed_ais_fields["mmsi"].is_number_unsigned()) {
        uint32_t mmsi_val = parsed_ais_fields["mmsi"].get<uint32_t>();
        mmsi_str = fmt::format("{:09u}", mmsi_val); // Ensure 9 digits, zero-padded
    } else if (parsed_ais_fields.count("mmsi") && parsed_ais_fields["mmsi"].is_string()) {
        mmsi_str = parsed_ais_fields["mmsi"].get<std::string>();
        // Optional: Validate mmsi_str format if needed, e.g., length and digits
        if (mmsi_str.length() != 9 || !std::all_of(mmsi_str.begin(), mmsi_str.end(), ::isdigit)) {
            _MSG_DEBUG("AIS: MMSI string from parser is invalid: {}. Raw: {}", mmsi_str, raw_aivdm_sentence);
            return false;
        }
    } else {
        _MSG_DEBUG("AIS: MMSI not found or invalid in parsed AIVDM/JSON. Raw sentence: {}", raw_aivdm_sentence);
        return false;
    }

    // MAC address generation must happen after mmsi_str is finalized.
    mac_addr ais_mac = mmsi_to_mac(mmsi_str);
    if (ais_mac.is_zero()) {
        _MSG_ERROR("Failed to generate MAC from MMSI: {}", mmsi_str);
        return false;
    }

    auto common = packet->fetch_or_add<kis_common_info>(pack_comp_common);
    common->type = packet_basic_data; // Generic data type
    common->phyid = fetch_phy_id();
    // AIS channels: AIS 1 (161.975 MHz) and AIS 2 (162.025 MHz)
    // We don't know the exact one without more info, pick one or use a default.
    // Some AIS receivers might report frequency in the JSON.
    if (json_data.count("frequency") && json_data["frequency"].is_number()) {
        common->freq_khz = json_data["frequency"].get<unsigned int>() / 1000;
    } else if (parsed_ais_fields.count("channel") && parsed_ais_fields["channel"].is_string()) {
        std::string chan = parsed_ais_fields["channel"].get<std::string>();
        if (chan == "A") common->freq_khz = 161975; // AIS Channel A is 161.975 MHz
        else if (chan == "B") common->freq_khz = 162025; // AIS Channel B is 162.025 MHz
        else common->freq_khz = 161975; // Default to A if unknown string
    } else {
        common->freq_khz = 161975; // Default to AIS channel 1 (A)
    }
    common->source = ais_mac;
    common->transmitter = ais_mac;
    // signal info can be added if available in json_data

    kis_lock_guard<kis_mutex> lk(devicetracker_obj_->get_devicelist_mutex(), "ais_process_json");

    std::shared_ptr<kis_tracked_device_base> basedev =
        devicetracker_obj_->update_common_device(common, common->source, this, packet,
                                               (UCD_UPDATE_FREQUENCIES | UCD_UPDATE_PACKETS | UCD_UPDATE_SEENBY),
                                               "AIS");

    if (basedev == nullptr) {
        _MSG_ERROR("Failed to update common device for MMSI {}", mmsi_str);
        return false;
    }

    basedev->set_manuf(ais_manuf);
    basedev->set_tracker_type_string(devicetracker_obj_->get_cached_devicetype("AIS Vessel"));
    // Set initial device name to MMSI, update with vessel name if available
    basedev->set_devicename(fmt::format("AIS {}", mmsi_str));

    auto aisdev = basedev->get_sub_as<ais_tracked_ais>(ais_device_id);
    bool new_ais = false;
    if (aisdev == nullptr) {
        aisdev = Globalreg::globalreg->entrytracker->get_shared_instance_as<ais_tracked_ais>(ais_device_id);
        if (aisdev == nullptr) {
            _MSG_FATAL("Could not get shared instance for ais_tracked_ais");
            return false; // Should not happen
        }
        basedev->insert(aisdev);
        new_ais = true;
    }

    // Populate aisdev with parsed data
    aisdev->set_mmsi(mmsi_str);
    basedev->add_field(mmsi_id, mmsi_str);

    // Vessel Name (from type 5, or other types that might provide it)
    if (parsed_ais_fields.count("vessel_name") && parsed_ais_fields["vessel_name"].is_string()) {
        std::string vn = parsed_ais_fields["vessel_name"].get<std::string>();
        if (!vn.empty()) {
            aisdev->set_vessel_name(vn);
            basedev->set_devicename(fmt::format("{} ({})", vn, mmsi_str)); // Update device name
            basedev->add_field(vessel_name_id, vn);
        }
    } else if (parsed_ais_fields.count("shipname") && parsed_ais_fields["shipname"].is_string()) { // Common alternative key
        std::string vn = parsed_ais_fields["shipname"].get<std::string>();
         if (!vn.empty()) {
            aisdev->set_vessel_name(vn);
            basedev->set_devicename(fmt::format("{} ({})", vn, mmsi_str));
            basedev->add_field(vessel_name_id, vn);
        }
    } else if (parsed_ais_fields.count("name") && parsed_ais_fields["name"].is_string()){ // Another common alternative
        std::string vn = parsed_ais_fields["name"].get<std::string>();
        if (!vn.empty()) {
            aisdev->set_vessel_name(vn);
            basedev->set_devicename(fmt::format("{} ({})", vn, mmsi_str));
            basedev->add_field(vessel_name_id, vn);
        }
    }


    // Callsign (from type 5)
    if (parsed_ais_fields.count("callsign") && parsed_ais_fields["callsign"].is_string()) {
        std::string cs = parsed_ais_fields["callsign"].get<std::string>();
        if (!cs.empty()){
            aisdev->set_callsign(cs);
            basedev->add_field(callsign_id, cs);
        }
    }

    // IMO Number (from type 5)
    if (parsed_ais_fields.count("imo_number") && parsed_ais_fields["imo_number"].is_number_unsigned()) {
        uint32_t imo = parsed_ais_fields["imo_number"].get<uint32_t>();
        if (imo > 0 && imo <= 999999999) { // Valid IMO are 7 digits, but allow flexibility if parser gives more.
            aisdev->set_imo_number(imo);
            basedev->add_field(imo_id, imo);
        }
    } else if (parsed_ais_fields.count("imo") && parsed_ais_fields["imo"].is_number_unsigned()) { // common alternative key
         uint32_t imo = parsed_ais_fields["imo"].get<uint32_t>();
        if (imo > 0 && imo <= 999999999) {
            aisdev->set_imo_number(imo);
            basedev->add_field(imo_id, imo);
        }
    }


    // Ship Type (from type 5 or other static data messages)
    if (parsed_ais_fields.count("ship_type") && parsed_ais_fields["ship_type"].is_number_unsigned()) {
        aisdev->set_ship_type(parsed_ais_fields["ship_type"].get<uint32_t>());
        basedev->add_field(ship_type_id, parsed_ais_fields["ship_type"].get<uint32_t>());
    } else if (parsed_ais_fields.count("shiptype") && parsed_ais_fields["shiptype"].is_number_unsigned()) { // common alternative key
         aisdev->set_ship_type(parsed_ais_fields["shiptype"].get<uint32_t>());
        basedev->add_field(ship_type_id, parsed_ais_fields["shiptype"].get<uint32_t>());
    }

    // Navigational Status (from type 1,2,3)
    if (parsed_ais_fields.count("nav_status") && parsed_ais_fields["nav_status"].is_number_unsigned()) {
        aisdev->set_nav_status(parsed_ais_fields["nav_status"].get<uint32_t>());
        basedev->add_field(nav_status_id, parsed_ais_fields["nav_status"].get<uint32_t>());
    } else if (parsed_ais_fields.count("navstatus") && parsed_ais_fields["navstatus"].is_number_unsigned()) { // common alternative key
        aisdev->set_nav_status(parsed_ais_fields["navstatus"].get<uint32_t>());
        basedev->add_field(nav_status_id, parsed_ais_fields["navstatus"].get<uint32_t>());
    }

    // Destination (from type 5)
    if (parsed_ais_fields.count("destination") && parsed_ais_fields["destination"].is_string()) {
        std::string dest_str = parsed_ais_fields["destination"].get<std::string>();
        if(!dest_str.empty()){
            aisdev->set_destination(dest_str);
            basedev->add_field(destination_id, dest_str);
        }
    }

    // ETA (from type 5, usually string `eta_str` from our parser or MMDDHHMM)
    if (parsed_ais_fields.count("eta_str") && parsed_ais_fields["eta_str"].is_string()) {
        aisdev->set_eta(parsed_ais_fields["eta_str"].get<std::string>());
        basedev->add_field(eta_id, parsed_ais_fields["eta_str"].get<std::string>());
    } else if (parsed_ais_fields.count("eta") && parsed_ais_fields["eta"].is_string()) {
        aisdev->set_eta(parsed_ais_fields["eta"].get<std::string>());
        basedev->add_field(eta_id, parsed_ais_fields["eta"].get<std::string>());
    }


    if (new_ais) {
        _MSG_INFO("Detected new AIS device MMSI {}, Name: '{}'", mmsi_str, aisdev->get_vessel_name().empty() ? "N/A" : aisdev->get_vessel_name());
    }

    bool location_present = false;
    auto gpsinfo = packet->fetch_or_add<kis_gps_packinfo>(pack_comp_gps); // Fetch or add, then populate

    // Latitude & Longitude (from type 1,2,3 and others)
    if (parsed_ais_fields.count("lat") && parsed_ais_fields["lat"].is_number() &&
        parsed_ais_fields.count("lon") && parsed_ais_fields["lon"].is_number()) {
        gpsinfo->lat = parsed_ais_fields["lat"].get<double>();
        gpsinfo->lon = parsed_ais_fields["lon"].get<double>();
        gpsinfo->fix = 3; // Assume 3D fix for AIS
        gpsinfo->ts_sec = packet->ts.tv_sec;
        gpsinfo->ts_usec = packet->ts.tv_usec;
        location_present = true;
    }

    // Altitude (rarely in AIS, but check)
    if (parsed_ais_fields.count("altitude") && parsed_ais_fields["altitude"].is_number()) {
        gpsinfo->alt = parsed_ais_fields["altitude"].get<double>();
    } else {
        gpsinfo->alt = 0; // AIS typically doesn't provide altitude
    }

    // Speed Over Ground (SOG)
    if (parsed_ais_fields.count("sog") && parsed_ais_fields["sog"].is_number()) {
        // AIS SOG is in knots. Kismet historically used m/s for gpsinfo->spd, but some UIs might expect km/h.
        // Let's stick to m/s for internal consistency with other GPS uses.
        // 1 knot = 0.514444 m/s
        gpsinfo->spd = parsed_ais_fields["sog"].get<double>() * 0.514444;
        location_present = true; // SOG often implies a valid position report
    } else if (parsed_ais_fields.count("speed") && parsed_ais_fields["speed"].is_number()){ // Alternative key
        gpsinfo->spd = parsed_ais_fields["speed"].get<double>() * 0.514444;
        location_present = true;
    }


    // Course Over Ground (COG) & True Heading
    if (parsed_ais_fields.count("cog") && parsed_ais_fields["cog"].is_number()) {
        double cog_val = parsed_ais_fields["cog"].get<double>();
         if (cog_val <= 360.0) { // COG is 0-359.9 degrees. Some sources might use 360 for N/A.
            gpsinfo->heading = cog_val;
            location_present = true;
        }
    } else if (parsed_ais_fields.count("true_heading") && parsed_ais_fields["true_heading"].is_number()) {
        uint16_t heading_val = parsed_ais_fields["true_heading"].get<uint16_t>();
        if (heading_val <= 359) { // Standard heading range 0-359
            gpsinfo->heading = static_cast<double>(heading_val);
            location_present = true;
        } // 511 means "not available", so we don't set heading in that case
    } else if (parsed_ais_fields.count("course") && parsed_ais_fields["course"].is_number()) { // Less specific alternative
        gpsinfo->heading = parsed_ais_fields["course"].get<double>();
        location_present = true;
    }


    if (location_present) {
        devicetracker_obj_->update_common_device(common, common->source, this, packet, UCD_UPDATE_LOCATION, "AIS Location");
        _MSG_DEBUG("Updated location for AIS MMSI {}: Lat {}, Lon {}", mmsi_str, gpsinfo->lat, gpsinfo->lon);
    }

    return true;
}

bool kis_ais_phy::parse_aivdm(const std::string& aivdm_sentence, nlohmann::json& parsed_ais_data) {
    if (aivdm_sentence.empty() || aivdm_sentence[0] != '!') {
        _MSG_DEBUG("AIS: AIVDM sentence does not start with '!': {}", aivdm_sentence);
        return false;
    }

    if (!kis_checksum_nmea_valid(aivdm_sentence)) {
        _MSG_DEBUG("AIS: Invalid NMEA checksum for sentence: {}", aivdm_sentence);
        return false;
    }

    // Extract content between '!' and '*'
    size_t start_marker = 1; // After '!'
    size_t end_marker = aivdm_sentence.rfind('*');
    if (end_marker == std::string::npos || end_marker <= start_marker) {
        _MSG_DEBUG("AIS: Malformed NMEA sentence, no checksum '*': {}", aivdm_sentence);
        return false;
    }
    std::string_view content_view(aivdm_sentence.data() + start_marker, end_marker - start_marker);

    std::vector<std::string> fields = split_string(std::string(content_view), ',');

    // Example: AIVDM,1,1,,A,133m@ogP00PD;88MD5MTDww@2D7k,0
    // fields[0] = AIVDM (or AIVDO, etc.)
    // fields[1] = fragment_count
    // fields[2] = fragment_number
    // fields[3] = message_id (sequential, optional)
    // fields[4] = channel (A or B)
    // fields[5] = encoded_payload
    // fields[6] = num_fill_bits
    if (fields.size() < 6 || fields.size() > 7) { // Typically 6 or 7 fields in the content part
        _MSG_DEBUG("AIS: AIVDM sentence has incorrect number of fields ({}): {}", fields.size(), std::string(content_view));
        return false;
    }

    try {
        parsed_ais_data["nmea_talker_id_type"] = fields[0]; // e.g., "AIVDM"
        if (fields[0] != "AIVDM" && fields[0] != "AIVDO") {
            _MSG_DEBUG("AIS: Not an AIVDM or AIVDO sentence type: {}", fields[0]);
            return false;
        }

        int fragment_count = std::stoi(fields[1]);
        int fragment_number = std::stoi(fields[2]);
        parsed_ais_data["fragment_count"] = fragment_count;
        parsed_ais_data["fragment_number"] = fragment_number;

        if (!fields[3].empty()) { // Sequential Message ID can be empty
            parsed_ais_data["message_id"] = fields[3];
        }
        parsed_ais_data["channel"] = fields[4]; // e.g., "A" or "B"
        std::string encoded_payload = fields[5];

        int num_fill_bits = 0;
        if (fields.size() > 6 && !fields[6].empty()) {
            // The 7th field (index 6) is the number of fill bits.
            // It should be a single digit '0'-'5'.
            if (fields[6].length() == 1 && fields[6][0] >= '0' && fields[6][0] <= '5') {
                 num_fill_bits = std::stoi(fields[6]);
            } else {
                _MSG_DEBUG("AIS: Invalid fill bits format: '{}' in sentence {}", fields[6], aivdm_sentence);
                // Default to 0 fill bits if format is unexpected but payload might be okay
            }
        }


        // Handle Multi-Fragment Messages (Basic)
        if (fragment_count > 1) {
            _MSG_DEBUG("AIS: Multi-fragment message received ({} of {}). Reassembly not yet fully supported.", fragment_number, fragment_count);
            if (fragment_number != 1) {
                // For now, only process the first fragment until reassembly is implemented.
                // Or, if reassembly is handled by the source, it should provide single combined payloads.
                return false;
            }
            // If it IS fragment 1 of N, we could potentially store it and wait for others.
            // For now, we will attempt to parse it as if it's a complete message,
            // which might be incorrect for some fields spanning multiple messages.
            // The AISParser classes expect a complete payload for a given message type.
        }

        // Use AISParser
        int message_type = 0;
        if (!encoded_payload.empty()) {
            // AISMessage::decode_6bit_ascii expects a single char, not the whole payload string.
            // The message type is the first 6 bits of the payload.
            message_type = AISParser::AISMessage::decode_6bit_ascii(encoded_payload[0]);
             // This is not entirely correct. decode_6bit_ascii gives value of first char.
            // The actual message type is derived from the first 6 bits of the *decoded binary stream*.
            // The AISMessage constructor handles this: it decodes the payload and extracts the type.
        } else {
            _MSG_DEBUG("AIS: Encoded payload is empty. Cannot determine message type. Sentence: {}", aivdm_sentence);
            return false;
        }

        // The AISMessage constructor will decode the payload and extract the true message type.
        // We pass 0 as a placeholder message_type to create_ais_message, as it will be determined internally.
        // Or rather, we should decode the first char to get the first 6 bits for the factory.
        
        // Correctly get message_type from first 6 bits of payload:
        if (encoded_payload.empty()) {
             _MSG_DEBUG("AIS: Encoded payload is empty. Cannot determine message type. Sentence: {}", aivdm_sentence);
            return false;
        }
        int first_char_val = AISParser::AISMessage::decode_6bit_ascii(encoded_payload[0]);
        if (first_char_val < 0) { // Error in decoding first char
             _MSG_DEBUG("AIS: Could not decode first character of payload: {}. Sentence: {}", encoded_payload[0], aivdm_sentence);
            return false;
        }
        message_type = first_char_val; // The message type is literally the first 6 bits (0-63)

        if (message_type <= 0 || message_type > 63) { // Type 0 is not valid.
            _MSG_DEBUG("AIS: Invalid message type {} decoded from payload start of: {}. Sentence: {}", message_type, encoded_payload.substr(0,1), aivdm_sentence);
            return false;
        }
        
        auto ais_msg = AISParser::create_ais_message(message_type, encoded_payload, num_fill_bits);

        if (ais_msg == nullptr) {
            // _MSG_DEBUG("AIS: Unsupported message type {} or error creating parser. Payload: {}", message_type, encoded_payload);
            // create_ais_message already logs for unsupported types.
            return false;
        }

        // The `ais_msg->parse()` will populate `parsed_ais_data` with specific fields.
        // It will include "mmsi", "lat", "lon", "ship_name", etc.
        ais_msg->parse(parsed_ais_data);

        // Add raw NMEA fields as well for context if needed later or for debugging
        parsed_ais_data["raw_nmea_payload"] = encoded_payload;
        parsed_ais_data["num_fill_bits"] = num_fill_bits;


    } catch (const std::invalid_argument& ia) {
        _MSG_ERROR("AIS: Invalid argument during NMEA parsing (stoi): {}. Sentence: {}", ia.what(), aivdm_sentence);
        return false;
    } catch (const std::out_of_range& oor) {
        _MSG_ERROR("AIS: Out of range during NMEA parsing (stoi): {}. Sentence: {}", oor.what(), aivdm_sentence);
        return false;
    } catch (const std::exception& e) {
        _MSG_ERROR("AIS: Exception during AIVDM NMEA processing: {}. Sentence: {}", e.what(), aivdm_sentence);
        return false;
    }
    
    return true;
}

// ais_tracked_ais members are in the header for now as they are simple.
// If they become more complex, they can be moved to the .cc file.
// tracker_element_base* ais_tracked_ais::clone() const { ... }
// void ais_tracked_ais::to_json(nlohmann::json& Rjson) const { ... }
// void ais_tracked_ais::from_json(nlohmann::json& Rjson) { ... }
// void ais_tracked_ais::render_data(...) { ... }
// These would be needed for full tracker_element_base implementation.
// For now, direct member access and simple getters/setters are used.

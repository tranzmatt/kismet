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

#ifndef __PHY_AIS_H__
#define __PHY_AIS_H__

#include "config.h"
#include "kis_phy_handler.h"
#include "packetchain.h"
#include "entrytracker.h"
#include "devicetracker.h"
#include "messagebus.h"
#include "kis_json_packinfo.h"
#include "macaddr.h"
#include "uuid.h"
#include "tracker_element.h"
#include "tracker_element_string.h"
#include "tracker_element_uint.h"
#include "kis_manuf.h"

#include <nlohmann/json.hpp>

// Forward declaration
class kis_packet;
class kis_tracked_device_base;
class kis_manuf_entry;

class ais_tracked_ais : public tracker_element_base {
public:
    ais_tracked_ais() { }
    ~ais_tracked_ais() { }

    virtual tracker_element_base* clone() const override {
        return new ais_tracked_ais(*this);
    }

    std::string mmsi;
    std::string vessel_name;
    std::string callsign;
    uint32_t imo_number = 0;
    uint32_t ship_type = 0;
    uint32_t nav_status = 0;
    std::string destination;
    std::string eta; // Could be timestamp in future

    // Basic getters for now, can add setters if needed
    const std::string& get_mmsi() const { return mmsi; }
    const std::string& get_vessel_name() const { return vessel_name; }
    const std::string& get_callsign() const { return callsign; }
    uint32_t get_imo_number() const { return imo_number; }
    uint32_t get_ship_type() const { return ship_type; }
    uint32_t get_nav_status() const { return nav_status; }
    const std::string& get_destination() const { return destination; }
    const std::string& get_eta() const { return eta; }

    void set_mmsi(const std::string& in_mmsi) { mmsi = in_mmsi; }
    void set_vessel_name(const std::string& in_vessel_name) { vessel_name = in_vessel_name; }
    void set_callsign(const std::string& in_callsign) { callsign = in_callsign; }
    void set_imo_number(uint32_t in_imo) { imo_number = in_imo; }
    void set_ship_type(uint32_t in_type) { ship_type = in_type; }
    void set_nav_status(uint32_t in_status) { nav_status = in_status; }
    void set_destination(const std::string& in_dest) { destination = in_dest; }
    void set_eta(const std::string& in_eta) { eta = in_eta; }
};

class kis_ais_phy : public kis_phy_handler {
public:
    kis_ais_phy(int in_phyid);
    virtual ~kis_ais_phy();

    static int packet_handler(CHAINCALL_PARMS);

    // Helper methods
    mac_addr mmsi_to_mac(const std::string& mmsi);
    bool process_ais_json(nlohmann::json& json_data, const std::shared_ptr<kis_packet>& packet);
    bool parse_aivdm(const std::string& aivdm_sentence, nlohmann::json& parsed_ais_data);

    // Packet component IDs
    int pack_comp_common;
    int pack_comp_json;
    int pack_comp_meta;
    int pack_comp_gps;
    int pack_comp_kisdatasrc;

    // Tracker field IDs
    tracker_field_id_t ais_device_id;
    tracker_field_id_t mmsi_id;
    tracker_field_id_t vessel_name_id;
    tracker_field_id_t callsign_id;
    tracker_field_id_t imo_id;
    tracker_field_id_t ship_type_id;
    tracker_field_id_t nav_status_id;
    tracker_field_id_t destination_id;
    tracker_field_id_t eta_id;

    std::shared_ptr<kis_manuf_entry> ais_manuf;

private:
    packet_chain* packetchain_obj_ = nullptr;
    entry_tracker* entrytracker_obj_ = nullptr;
    device_tracker* devicetracker_obj_ = nullptr;
};

#endif // __PHY_AIS_H__

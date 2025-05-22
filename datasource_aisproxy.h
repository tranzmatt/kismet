/*
    This file is part of Kismet
    Copyright (C) 2003-2023 Kismet Wireless, LLC
    SPDX-License-Identifier: GPL-2.0-or-later
    Full license text available in COPYING
*/

#ifndef __DATASOURCE_AISPROXY_H__
#define __DATASOURCE_AISPROXY_H__

#include "config.h"

#include "kis_datasource.h"
// Potentially include datasource_virtual.h if it's to be a virtual source,
// but for a simple proxy, direct inheritance from kis_datasource might be sufficient
// if the external tool handles the "virtual" nature.
// For consistency with adsbproxy, let's assume it might use some virtual source capabilities
// or that the external Python script acts like one.
// #include "datasource_virtual.h" // Let's omit this for now unless strictly needed by builder pattern

class kis_datasource_aisproxy;
typedef std::shared_ptr<kis_datasource_aisproxy> shared_datasource_aisproxy;

class kis_datasource_aisproxy : public kis_datasource {
public:
    kis_datasource_aisproxy(std::shared_ptr<kis_datasource_builder> in_builder) :
        kis_datasource(in_builder) {
        // Set hardware type and the binary Kismet will try to run
        // The binary 'kismet_cap_ais_proxy' will be a Python script
        set_int_source_hardware("aisproxy");
        set_int_source_ipc_binary("kismet_cap_ais_proxy"); 
        // AIS data typically has its own location, so Kismet's GPS shouldn't override source GPS
        suppress_gps = true; 
    }

    virtual ~kis_datasource_aisproxy() { }

protected:
    // Override open_interface if specific logic is needed, otherwise base class is fine
    // virtual void open_interface(std::string in_definition, unsigned int in_transaction,
    //         open_callback_t in_cb) override {
    //     kis_datasource::open_interface(in_definition, in_transaction, in_cb);
    // }
};

class datasource_aisproxy_builder : public kis_datasource_builder {
public:
    datasource_aisproxy_builder() :
        kis_datasource_builder() {
        register_fields();
        reserve_fields(nullptr); // Pass nullptr if no specific fields from a map needed at init
        initialize();
    }

    datasource_aisproxy_builder(int in_id) :
        kis_datasource_builder(in_id) {
        register_fields();
        reserve_fields(nullptr);
        initialize();
    }

    datasource_aisproxy_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_datasource_builder(in_id, e) {
        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual ~datasource_aisproxy_builder() { }

    virtual std::shared_ptr<kis_datasource> build_datasource(std::shared_ptr<kis_datasource_builder> in_sh_this) override {
        // Corrected to match the pattern in Kismet, ensuring 'this' is correctly passed if needed by shared_from_this logic
        return std::make_shared<kis_datasource_aisproxy>(in_sh_this);
    }

    virtual void initialize() override {
        set_source_type("aisproxy");
        set_source_description("AIS AIVDM/AIVDO stream proxy");

        // AIS proxy is typically a local or remote connection to an existing feed
        set_probe_capable(false); // Cannot probe for interfaces
        set_list_capable(false);  // Cannot list interfaces in the traditional sense
        set_local_capable(true);  // Can be defined as a local command/script
        set_remote_capable(true); // Can connect to a remote TCP feed via the script
        set_passive_capable(false); // Not passive in the Kismet sense
        set_tune_capable(false);  // No frequency tuning via Kismet
        set_hop_capable(false);   // No hopping
    }
};

#endif // __DATASOURCE_AISPROXY_H__

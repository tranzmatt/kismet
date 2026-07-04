/*
   This file is part of Kismet

   Kismet is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   Kismet is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with Kismet; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef __PHY_80211_COMPONENTS_V2__
#define __PHY_80211_COMPONENTS_V2__

#include "boost/beast/core/detail/base64.hpp"
#include "config.h"

#ifdef HAVE_LIBPCRE1
#include <pcre.h>
#endif

#ifdef HAVE_LIBPCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

#include "base64.h"
#include "globalregistry.h"
#include "json_adapter_v2.h"
#include "macaddr.h"
#include "packet.h"
#include "packinfo_signal.h"
#include "rrd_v2.h"
#include "trackedlocation_v2.h"

#include "dot11_parsers/dot11_ie.h"
#include "dot11_parsers/dot11_ie_221_vendor.h"
#include "dot11_parsers/dot11_ie_255_ext_tag.h"

class dot11_tracked_eapol_v2 : public json_adapter_v2::jsonable {
public:
    dot11_tracked_eapol_v2() :
        json_adapter_v2::jsonable() {
        reset();
    }

    dot11_tracked_eapol_v2& operator =(const dot11_tracked_eapol_v2& e) {
        eapol_time_ = e.eapol_time_;
        eapol_dir_ = e.eapol_dir_;
        eapol_replay_counter_ = e.eapol_replay_counter_;
        eapol_msg_num_ = e.eapol_msg_num_;
        eapol_install_ = e.eapol_install_;
        eapol_nonce_ = e.eapol_nonce_;
        eapol_rsn_pmkid_ = e.eapol_rsn_pmkid_;
        packet_ = e.packet_;
        return *this;
    }

    void reset() {
        eapol_time_ = 0;
        eapol_dir_ = 0;
        eapol_replay_counter_ = 0;
        eapol_msg_num_ = 0;
        eapol_install_ = 0;
        eapol_nonce_ = {};
        eapol_rsn_pmkid_ = {};
        packet_ = {};
    }

    auto eapol_time() const { return eapol_time_; }
    void set_eapol_time(auto time) { eapol_time_ = time; }

    auto eapol_dir() const { return eapol_dir_; };
    void set_eapol_dir(auto dir) { eapol_dir_ = dir; }

    auto eapol_replay_counter() const { return eapol_replay_counter_; }
    void set_eapol_replay_counter(auto c) { eapol_replay_counter_ = c; }

    auto eapol_msg_num() const { return eapol_msg_num_; }
    void set_eapol_msg_num(auto num) { eapol_msg_num_ = num; }

    auto eapol_install() const { return eapol_install_; }
    void set_eapol_install(auto i) { eapol_install_ = i; }

    const auto& eapol_nonce() const { return eapol_nonce_; }
    void set_eapol_nonce(const auto& nonce) { eapol_nonce_ = base64::encode(nonce); }

    const auto& eapol_rsn_pmkid() const { return eapol_rsn_pmkid_; }
    void set_eapol_rsn_pmkid(const auto& pmk) { eapol_rsn_pmkid_ = base64::encode(pmk); }

    const auto& packet() const { return packet_; }
    void set_packet(const auto& packet) { packet_ = packet; }

    void as_json(std::ostream& os, json_adapter_v2::opts *opts) {
        fmt::print(os, "{{");

        auto sv_comma = opts->next_key_comma;
        opts->next_key_comma = false;

        json_adapter_v2::json_encode_keyed<double>{}(os, "dot11.eapol.timestamp", opts, eapol_time());
        json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.eapol.direction", opts, eapol_dir());
        json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.eapol.replay_counter", opts, eapol_replay_counter());
        json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.eapol.message_num", opts, eapol_msg_num());
        json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.eapol.install", opts, eapol_install());
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.eapol.nonce", opts, eapol_nonce());
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.eapol.rsn_pmkid", opts, eapol_rsn_pmkid());
        json_adapter_v2::json_encode_keyed<kis_tracked_packet_v2>{}(os, "dot11.eapol.packet", opts, packet_);

        opts->next_key_comma = sv_comma;

        fmt::print(os, "}}");
    }

    void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) {
        if (fields.size() == 0) {
            return as_json(os, opts);
        }

        auto sv_comma = opts->next_key_comma;
        opts->next_key_comma = false;

        json_adapter_v2::field_group_map subgroup;

        fmt::print(os, "{{");
        for (const auto& f : fields) {
            switch (json_adapter_v2::consthash(f.first)) {
                case json_adapter_v2::consthash("dot11.eapol.timestamp"):
                    json_adapter_v2::json_encode_keyed<double>{}(os, f.second.rename, opts, eapol_time());
                    break;
                case json_adapter_v2::consthash("dot11.eapol.direction"):
                    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, eapol_dir());
                    break;
                case json_adapter_v2::consthash("dot11.eapol.replay_counter"):
                    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, eapol_replay_counter());
                    break;
                case json_adapter_v2::consthash("dot11.eapol.message_num"):
                    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, eapol_msg_num());
                    break;
                case json_adapter_v2::consthash("dot11.eapol.install"):
                    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, eapol_install());
                    break;
                case json_adapter_v2::consthash("dot11.eapol.nonce"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, eapol_nonce());
                    break;
                case json_adapter_v2::consthash("dot11.eapol.rsn_pmkid"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, eapol_rsn_pmkid());
                    break;
                case json_adapter_v2::consthash("dot11.eapol.packet"):
                    json_adapter_v2::group_fields(f.second.subfields, subgroup);
                    json_adapter_v2::json_encode_keyed<kis_tracked_packet_v2>{}(os, f.second.rename, opts, packet_, subgroup);
                default:
                    json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
            }
        }

        fmt::print(os, "}}");
        opts->next_key_comma = sv_comma;
    }


protected:
    double eapol_time_;
    uint8_t eapol_dir_;
    uint64_t eapol_replay_counter_;
    uint8_t eapol_msg_num_;
    uint8_t eapol_install_;
    std::string eapol_nonce_;
    std::string eapol_rsn_pmkid_;
    kis_tracked_packet_v2 packet_;
};

template<> struct json_adapter_v2::json_encode<dot11_tracked_eapol_v2> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_eapol_v2& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_eapol_v2 *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_eapol_v2& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_eapol_v2 *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
};

class dot11_tracked_nonce_v2 : public json_adapter_v2::jsonable {
public:
    dot11_tracked_nonce_v2() :
        json_adapter_v2::jsonable() {
        reset();
    }

    dot11_tracked_nonce_v2& operator =(const dot11_tracked_nonce_v2& e) {
        eapol_time_ = e.eapol_time_;
        eapol_replay_counter_ = e.eapol_replay_counter_;
        eapol_msg_num_ = e.eapol_msg_num_;
        eapol_install_ = e.eapol_install_;
        eapol_nonce_ = e.eapol_nonce_;
        return *this;
    }

    void reset() {
        eapol_time_ = 0;
        eapol_replay_counter_ = 0;
        eapol_msg_num_ = 0;
        eapol_install_ = 0;
        eapol_nonce_ = {};
    }

    auto eapol_time() const { return eapol_time_; }
    void set_eapol_time(auto time) { eapol_time_ = time; }

    auto eapol_replay_counter() const { return eapol_replay_counter_; }
    void set_eapol_replay_counter(auto c) { eapol_replay_counter_ = c; }

    auto eapol_msg_num() const { return eapol_msg_num_; }
    void set_eapol_msg_num(auto num) { eapol_msg_num_ = num; }

    auto eapol_install() const { return eapol_install_; }
    void set_eapol_install(auto i) { eapol_install_ = i; }

    const auto& eapol_nonce() const { return eapol_nonce_; }
    void set_eapol_nonce(const auto& nonce) { eapol_nonce_ = base64::encode(nonce); }

    void as_json(std::ostream& os, json_adapter_v2::opts *opts) {
        fmt::print(os, "{{");

        auto sv_comma = opts->next_key_comma;
        opts->next_key_comma = false;

        json_adapter_v2::json_encode_keyed<double>{}(os, "dot11.eapol.timestamp", opts, eapol_time());
        json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.eapol.replay_counter", opts, eapol_replay_counter());
        json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.eapol.message_num", opts, eapol_msg_num());
        json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.eapol.install", opts, eapol_install());
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.eapol.nonce", opts, eapol_nonce());

        opts->next_key_comma = sv_comma;

        fmt::print(os, "}}");
    }

    void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) {
        if (fields.size() == 0) {
            return as_json(os, opts);
        }

        auto sv_comma = opts->next_key_comma;
        opts->next_key_comma = false;

        json_adapter_v2::field_group_map subgroup;

        fmt::print(os, "{{");
        for (const auto& f : fields) {
            switch (json_adapter_v2::consthash(f.first)) {
                case json_adapter_v2::consthash("dot11.eapol.timestamp"):
                    json_adapter_v2::json_encode_keyed<double>{}(os, f.second.rename, opts, eapol_time());
                    break;
                case json_adapter_v2::consthash("dot11.eapol.replay_counter"):
                    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, eapol_replay_counter());
                    break;
                case json_adapter_v2::consthash("dot11.eapol.message_num"):
                    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, eapol_msg_num());
                    break;
                case json_adapter_v2::consthash("dot11.eapol.install"):
                    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, eapol_install());
                    break;
                case json_adapter_v2::consthash("dot11.eapol.nonce"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, eapol_nonce());
                    break;
                default:
                    json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
            }
        }

        fmt::print(os, "}}");
        opts->next_key_comma = sv_comma;
    }

protected:
    double eapol_time_;
    uint8_t eapol_msg_num_;
    uint8_t eapol_install_;
    std::string eapol_nonce_;
    uint64_t eapol_replay_counter_;
};

template<> struct json_adapter_v2::json_encode<dot11_tracked_nonce_v2> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_nonce_v2& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_nonce_v2 *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_nonce_v2& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_nonce_v2 *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
};

// v2 does not include an internal mutex; safe access & comparison should be handled by the
// enclosing api
class dot11_tracked_ssid_alert_v2 : public json_adapter_v2::jsonable {
public:
    dot11_tracked_ssid_alert_v2() :
        json_adapter_v2::jsonable() {
        reset();
    }

    virtual ~dot11_tracked_ssid_alert_v2() {
#if defined(HAVE_LIBPCRE1)
        if (ssid_re_ != NULL)
            pcre_free(ssid_re_);
        if (ssid_study_ != NULL)
            pcre_free(ssid_study_);
#elif defined(HAVE_LIBPCRE2)
        if (ssid_match_data_ != NULL)
            pcre2_match_data_free(ssid_match_data_);
        if (ssid_re_ != NULL)
            pcre2_code_free(ssid_re_);
#endif
    }

    void reset() {
#if defined(HAVE_LIBPCRE1)
        if (ssid_re_ != NULL)
            pcre_free(ssid_re_);
        if (ssid_study_ != NULL)
            pcre_free(ssid_study_);

        ssid_re_ = NULL;
        ssid_study_ = NULL;
#elif defined(HAVE_LIBPCRE2)
        if (ssid_match_data_ != NULL)
            pcre2_match_data_free(ssid_match_data_);
        if (ssid_re_ != NULL)
            pcre2_code_free(ssid_re_);

        ssid_match_data_ = NULL;
        ssid_re_ = NULL;
#endif

        ssid_group_name_ = {};
        ssid_regex_ = {};
        allowed_macs_vec_ = {};
    }

    const auto ssid_group_name() { return ssid_group_name_; }
    void set_ssid_group_name(auto name) { ssid_group_name_ = name; }

    const auto ssid_regex() { return ssid_regex_; }
    void set_ssid_regex(const std::string& regex) {
#if defined(HAVE_LIBPCRE1)
        const char *compile_error, *study_error;
        int erroroffset;

        if (ssid_re_)
            pcre_free(ssid_re_);
        if (ssid_study_)
            pcre_free(ssid_study_);

        ssid_regex_ = regex;

        ssid_re_ = pcre_compile(regex.c_str(), 0, &compile_error, &erroroffset, NULL);

        if (ssid_re_ == NULL) {
            throw std::runtime(fmt::format("Could not parse PCRE: {} at {}",
                        compile_error, erroroffset));
        }

        ssid_study_ = pcre_study(ssid_re_, 0, &study_error);

        if (study_error != NULL) {
            throw std::runtime_error(fmt::format("PCRE error: {}", study_error));
        }
#elif defined(HAVE_LIBPCRE2)
        PCRE2_SIZE erroroffset;
        int errornumber;

        if (ssid_match_data_)
            pcre2_match_data_free(ssid_match_data_);
        if (ssid_re_)
            pcre2_code_free(ssid_re_);

        ssid_regex_ = regex;

        ssid_re_ = pcre2_compile((PCRE2_SPTR8) regex.c_str(),
                PCRE2_ZERO_TERMINATED, 0, &errornumber, &erroroffset, NULL);

        if (ssid_re_ == nullptr) {
            PCRE2_UCHAR buffer[256];
            pcre2_get_error_message(errornumber, buffer, sizeof(buffer));
            const auto e = fmt::format("Could not parse PCRE regex: {} at {}",
                    (int) erroroffset, (char *) buffer);
            throw std::runtime_error(e);
        }

        ssid_match_data_ = pcre2_match_data_create_from_pattern(ssid_re_, NULL);
#endif
    }

    const auto& allowed_macs() { return allowed_macs_vec_; }
    void set_allowed_macs(const auto& macs) { allowed_macs_vec_ = macs; }

    bool compare_ssid(const std::string& ssid, const mac_addr& mac) {
#if defined(HAVE_LIBPCRE1) || defined(HAVE_LIBPCRE2)
        int rc;
#if defined(HAVE_LIBPCRE1)
        int ovector[128];
        rc = pcre_exec(ssid_re_, ssid_study_, ssid.c_str(), ssid.length(), 0, 0, ovector, 128);
#elif defined(HAVE_LIBPCRE2)
        rc = pcre2_match(ssid_re_, (PCRE2_SPTR8) ssid.c_str(), ssid.length(),
                0, 0, ssid_match_data_, NULL);
#endif
        if (rc > 0) {
            bool valid = false;

            for (const auto& m : allowed_macs_vec_) {
                if (m == mac) {
                    valid = true;
                    break;
                }
            }

            if (!valid)
                return true;
        }
#endif
        return false;
    }

    void as_json(std::ostream& os, json_adapter_v2::opts *opts) {
        fmt::print(os, "{{");

        auto sv_comma = opts->next_key_comma;
        opts->next_key_comma = false;

        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.ssidalert.name", opts, ssid_group_name_);
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.ssidalert.regex", opts, ssid_regex_);
        json_adapter_v2::json_encode_keyed_array<allowed_macs_vec_iter_t_>{}(os, "dot11.ssidalert.allowed_macs", opts,
                allowed_macs_vec_.begin(), allowed_macs_vec_.end());

        opts->next_key_comma = sv_comma;

        fmt::print(os, "}}");
    }

    void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) {
        if (fields.size() == 0) {
            return as_json(os, opts);
        }

        auto sv_comma = opts->next_key_comma;
        opts->next_key_comma = false;

        fmt::print(os, "{{");
        for (const auto& f : fields) {
            switch (json_adapter_v2::consthash(f.first)) {
                case json_adapter_v2::consthash("dot11.ssidalert.name"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, ssid_group_name_);
                    break;
                case json_adapter_v2::consthash("dot11.ssidalert.regex"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, ssid_regex_);
                    break;
                case json_adapter_v2::consthash("dot11.ssidalert.allowed_macs"):
                    json_adapter_v2::json_encode_keyed_array<allowed_macs_vec_iter_t_>{}(os, f.second.rename, opts,
                            allowed_macs_vec_.begin(), allowed_macs_vec_.end());
                    break;
                default:
                    json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
            }
        }

        fmt::print(os, "}}");
        opts->next_key_comma = sv_comma;
    }

protected:
    std::string ssid_group_name_;
    std::string ssid_regex_;

    using allowed_macs_vec_iter_t_ = std::vector<mac_addr>::iterator;
    std::vector<mac_addr> allowed_macs_vec_;

#if defined(HAVE_LIBPCRE1)
    pcre *ssid_re_;
    pcre_extra *ssid_study_;
#elif defined(HAVE_LIBPCRE2)
    pcre2_code *ssid_re_;
    pcre2_match_data *ssid_match_data_;
#endif
};

template<> struct json_adapter_v2::json_encode<dot11_tracked_ssid_alert_v2> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_ssid_alert_v2& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_ssid_alert_v2 *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_ssid_alert_v2& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_ssid_alert_v2 *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
};


class dot11_11d_tracked_range_info_v2 : public json_adapter_v2::jsonable {
public:
    dot11_11d_tracked_range_info_v2() :
        json_adapter_v2::jsonable() {
        reset();
    }

    dot11_11d_tracked_range_info_v2(const dot11_11d_tracked_range_info_v2& d) {
        startchan_ = d.startchan_;
        numchan_ = d.numchan_;
        txpower_ = d.txpower_;
    }

    dot11_11d_tracked_range_info_v2& operator=(const dot11_11d_tracked_range_info_v2& d) {
        startchan_ = d.startchan_;
        numchan_ = d.numchan_;
        txpower_ = d.txpower_;
        return *this;
    }

    void reset() {
        startchan_ = 0;
        numchan_ = 0;
        txpower_ = 0;
    }

    auto startchan() { return startchan_; }
    void set_startchan(auto start) { startchan_ = start; }

    auto numchan() { return numchan_; }
    void set_numchan(auto num) { numchan_ = num; }

    auto txpower() { return txpower_; }
    void set_txpower(auto pow) { txpower_ = pow; }

    void as_json(std::ostream& os, json_adapter_v2::opts *opts) {
        fmt::print(os, "{{");

        auto sv_comma = opts->next_key_comma;
        opts->next_key_comma = false;

        json_adapter_v2::json_encode_keyed<uint32_t>{}(os, "dot11.11d.start_channel", opts, startchan_);
        json_adapter_v2::json_encode_keyed<uint32_t>{}(os, "dot11.11d.num_channels", opts, numchan_);
        json_adapter_v2::json_encode_keyed<int32_t>{}(os, "dot11.11d.tx_power", opts, txpower_);

        opts->next_key_comma = sv_comma;

        fmt::print(os, "}}");
    }

    void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) {
        if (fields.size() == 0) {
            return as_json(os, opts);
        }

        auto sv_comma = opts->next_key_comma;
        opts->next_key_comma = false;

        fmt::print(os, "{{");
        for (const auto& f : fields) {
            switch (json_adapter_v2::consthash(f.first)) {
                case json_adapter_v2::consthash("dot11.11d.start_channel"):
                    json_adapter_v2::json_encode_keyed<uint32_t>{}(os, f.second.rename, opts, startchan_);
                    break;
                case json_adapter_v2::consthash("dot11.11d.num_channels"):
                    json_adapter_v2::json_encode_keyed<uint32_t>{}(os, f.second.rename, opts, numchan_);
                    break;
                case json_adapter_v2::consthash("dot11.11d.tx_power"):
                    json_adapter_v2::json_encode_keyed<int32_t>{}(os, f.second.rename, opts, txpower_);
                    break;
                default:
                    json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
            }
        }

        fmt::print(os, "}}");
        opts->next_key_comma = sv_comma;
    }
protected:
    uint32_t startchan_;
    uint32_t numchan_;
    int32_t txpower_;
};

template<> struct json_adapter_v2::json_encode<dot11_11d_tracked_range_info_v2> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_11d_tracked_range_info_v2& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_11d_tracked_range_info_v2 *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_11d_tracked_range_info_v2& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_11d_tracked_range_info_v2 *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
};


class dot11_tracked_ietag_v2 : public json_adapter_v2::jsonable {
public:
    dot11_tracked_ietag_v2() :
        json_adapter_v2::jsonable() { }

    dot11_tracked_ietag_v2& operator=(const dot11_tracked_ietag_v2& t) {
        unique_tag_id_ = t.unique_tag_id_;
        tag_number_ = t.tag_number_;
        tag_oui_ = t.tag_oui_;
        tag_oui_manuf_ = t.tag_oui_manuf_;
        tag_vendor_ = t.tag_vendor_;
        tag_data_ = t.tag_data_;

        return *this;
    }

    void reset() {
        unique_tag_id_ = 0;
        tag_number_ = 0;
        tag_oui_ = 0;
        tag_oui_manuf_ = {};
        tag_vendor_ = 0;
        tag_data_ = {};
    }

    auto unique_tag_id() { return unique_tag_id_; }
    void set_unique_tag_id(auto id) { unique_tag_id_ = id; }

    auto tag_number() { return tag_number_; }
    void set_tag_number(auto num) { tag_number_ = num; }

    auto tag_oui() { return tag_oui_; }
    void set_tag_oui(auto oui) { tag_oui_ = oui; }

    const auto& tag_oui_manuf() { return tag_oui_manuf_; }
    void set_tag_oui_manuf(const auto& manuf) { tag_oui_manuf_ = manuf; }

    auto tag_vendor() { return tag_vendor_; }
    void set_tag_vendor(auto v) { tag_vendor_ = v; }

    const auto& tag_data() { return tag_data_; }
    void set_tag_data(const auto& d) { tag_data_ = base64::encode(d); }

    void as_json(std::ostream& os, json_adapter_v2::opts *opts) {
        fmt::print(os, "{{");

        auto sv_comma = opts->next_key_comma;
        opts->next_key_comma = false;

        json_adapter_v2::json_encode_keyed<uint32_t>{}(os, "dot11.ietag.uniqueid", opts, unique_tag_id_);
        json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.ietag.number", opts, tag_number_);
        json_adapter_v2::json_encode_keyed<uint32_t>{}(os, "dot11.ietag.oui", opts, tag_oui_);
        json_adapter_v2::json_encode_keyed<std::string_view>{}(os, "dot11.ietag.oui_manuf", opts, tag_oui_manuf_);
        json_adapter_v2::json_encode_keyed<uint16_t>{}(os, "dot11.ietag.subtag", opts, tag_vendor_);
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.ietag.data", opts, tag_data_);

        opts->next_key_comma = sv_comma;

        fmt::print(os, "}}");
    }

    void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) {
        if (fields.size() == 0) {
            return as_json(os, opts);
        }

        auto sv_comma = opts->next_key_comma;
        opts->next_key_comma = false;

        fmt::print(os, "{{");
        for (const auto& f : fields) {
            switch (json_adapter_v2::consthash(f.first)) {
                case json_adapter_v2::consthash("dot11.ietag.uniqueid"):
                    json_adapter_v2::json_encode_keyed<uint32_t>{}(os, f.second.rename, opts, unique_tag_id_);
                    break;
                case json_adapter_v2::consthash("dot11.ietag.number"):
                    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, tag_number_);
                    break;
                case json_adapter_v2::consthash("dot11.ietag.oui"):
                    json_adapter_v2::json_encode_keyed<uint32_t>{}(os, f.second.rename, opts, tag_oui_);
                    break;
                case json_adapter_v2::consthash("dot11.ietag.oui_manuf"):
                    json_adapter_v2::json_encode_keyed<std::string_view>{}(os, f.second.rename, opts, tag_oui_manuf_);
                    break;
                case json_adapter_v2::consthash("dot11.ietag.subtag"):
                    json_adapter_v2::json_encode_keyed<uint16_t>{}(os, f.second.rename, opts, tag_vendor_);
                    break;
                case json_adapter_v2::consthash("dot11.ietag.data"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, tag_data_);
                    break;
                default:
                    json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
            }
        }

        fmt::print(os, "}}");
        opts->next_key_comma = sv_comma;
    }

protected:
    uint32_t unique_tag_id_;
    uint8_t tag_number_;
    uint32_t tag_oui_;
    std::string_view tag_oui_manuf_;
    uint16_t tag_vendor_;
    std::string tag_data_;
};

template<> struct json_adapter_v2::json_encode<dot11_tracked_ietag_v2> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_ietag_v2& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_ietag_v2 *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_ietag_v2& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_ietag_v2 *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
};

class dot11_probed_ssid_v2 : public json_adapter_v2::jsonable {
public:
    dot11_probed_ssid_v2() :
    json_adapter_v2::jsonable() {
        reset();
    }

    virtual ~dot11_probed_ssid_v2() { }

    void reset() {
        ssid_ = {};
        ssid_len_ = 0;

        bssid_ = {};

        first_time_ = 0;
        last_time_ = 0;

        location_ = {};

        dot11r_mobility_ = 0;
        dot11r_mobility_domain_ = 0;

        crypt_set_ = 0;
        crypt_string_ = {};

        wpa_mfp_required_ = 0;
        wpa_mfp_supported_ = 0;

        ie_tag_list_ = {};

        wps_version_ = 0;
        wps_state_ = 0;
        wps_config_methods_ = 0;
        wps_manuf_ = {};
        wps_device_name_ = {};
        wps_model_name_ = {};
        wps_model_number_ = {};
        wps_serial_number_ = {};
        wps_uuid_e_ = {};
    }

    const auto first_time() { return first_time_; }
    void set_first_time(auto time) { first_time_ = time; }
    void set_first_time_ifless(auto time) {
        if (time < first_time_) {
            first_time_ = time;
        }
    }

    const auto last_time() { return last_time_; }
    void set_last_time(auto time) { last_time_ = time; }
    void set_last_time_ifgreater(auto time) {
        if (last_time_ < time) {
            last_time_ = time;
        }
    }

    const auto& ssid() const { return ssid_; }
    void set_ssid(const auto& ssid) { ssid_ = ssid; }

    auto ssid_len() const { return ssid_len_; }
    void set_ssid_len(auto len) { ssid_len_ = len; }

    const auto& bssid() const { return bssid_; }
    void set_bssid(const auto& bssid) { bssid_ = bssid; }

    auto& location() const { return location_; }
    void set_location(const auto& loc) { location_ = loc; }

    auto dot11r_mobility() const { return dot11r_mobility_; }
    void set_dot11r_mobility(auto m) { dot11r_mobility_ = m; }

    auto dot11r_mobility_domain() const { return dot11r_mobility_domain_; }
    void set_dot11r_mobility_domain(auto d) { dot11r_mobility_domain_ = d; }

    auto crypt_set() const { return crypt_set_; }
    void set_crypt_set(auto s) { crypt_set_ = s; }

    const auto& crypt_string() const { return crypt_string_; }
    void set_crypt_string(const auto& c) { crypt_string_ = c; }

    auto wpa_mfp_required() const { return wpa_mfp_required_; }
    void set_wpa_mfp_required(auto r) { wpa_mfp_required_ = r; }

    auto wpa_mfp_supported() const { return wpa_mfp_supported_; }
    void set_wpa_mfp_supported(auto v) { wpa_mfp_supported_ = v; }

    auto& ie_tag_list() { return ie_tag_list_; }
    void set_ie_tag_list(const auto& v) { ie_tag_list_ = v; }

    auto wps_version() const { return wps_version_; }
    void set_wps_version(auto v) { wps_version_ = v; }

    auto wps_state() const { return wps_state_; }
    void set_wps_state(auto v) { wps_state_ = v; }

    auto wps_config_methods() const { return wps_config_methods_; }
    void set_wps_config_methods(auto v) { wps_config_methods_ = v; }

    const auto& wps_manuf() const { return wps_manuf_; }
    void set_wps_manuf(const auto& v) { wps_manuf_ = v; }

    const auto& wps_device_name() const { return wps_device_name_; }
    void set_wps_device_name(const auto& v) { wps_device_name_ = v; }

    const auto& wps_model_name() const { return wps_model_name_; }
    void set_wps_model_name(const auto& v) { wps_model_name_ = v; }

    const auto& wps_uuid_e() const { return wps_uuid_e_; }
    void set_wps_uuid_e(const auto& v) { wps_uuid_e_ = v; }

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override {
        fmt::print(os, "{{");

        auto sv_comma = opts->next_key_comma;
        opts->next_key_comma = false;

        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.probedssid.ssid", opts, ssid_);
        json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.probedssid.ssidlen", opts, ssid_len_);
        json_adapter_v2::json_encode_keyed<mac_addr>{}(os, "dot11.probedssid.bssid", opts, bssid_);

        json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.probedssid.first_time", opts, first_time_);
        json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.probedssid.last_time", opts, last_time_);

        json_adapter_v2::json_encode_keyed<kis_tracked_location_v2>{}(os, "dot11.probedssid.location", opts, location_);

        json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.probedssid.mobility_id", opts, dot11r_mobility_);
        json_adapter_v2::json_encode_keyed<uint16_t>{}(os, "dot11.probedssid.mobility_domain_id", opts, dot11r_mobility_domain_);

        json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.probedssid.crypt_bitfield", opts, crypt_set_);
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.probedssid.crypt_string", opts, crypt_string_);

        json_adapter_v2::json_encode_keyed<bool>{}(os, "dot11.probedssid.wpa_mfp_required", opts, wpa_mfp_required_);
        json_adapter_v2::json_encode_keyed<bool>{}(os, "dot11.probedssid.wpa_mfp_supported", opts, wpa_mfp_supported_);

        json_adapter_v2::json_encode_keyed_array<ie_tag_list_iter_t_>{}(os, "dot11.probedssid.ie_tag_list", opts,
                ie_tag_list_.begin(), ie_tag_list_.end());

        json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.probedssid.wps_version", opts, wps_version_);
        json_adapter_v2::json_encode_keyed<uint32_t>{}(os, "dot11.probedssid.wps_state", opts, wps_state_);
        json_adapter_v2::json_encode_keyed<uint16_t>{}(os, "dot11.probedssid.wps_config_methods", opts, wps_config_methods_);
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.probedssid.wps_manuf", opts, wps_manuf_);
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.probedssid.wps_device_name", opts, wps_device_name_);
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.probedssid.wps_model_name", opts, wps_model_name_);
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.probedssid.wps_model_number", opts, wps_model_number_);
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.probedssid.wps_serial_number", opts, wps_serial_number_);
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.probedssid.wps_uuid_e", opts, wps_uuid_e_);

        opts->next_key_comma = sv_comma;

        fmt::print(os, "}}");
    }

    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) override {
        if (fields.size() == 0) {
            return as_json(os, opts);
        }

        auto sv_comma = opts->next_key_comma;
        opts->next_key_comma = false;

        json_adapter_v2::field_group_map subgroup;

        fmt::print(os, "{{");
        for (const auto& f : fields) {
            switch (json_adapter_v2::consthash(f.first)) {
                case json_adapter_v2::consthash("dot11.probedssid.ssid"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, ssid_);
                    break;
                case json_adapter_v2::consthash("dot11.probedssid.ssidlen"):
                    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, ssid_len_);
                    break;
                case json_adapter_v2::consthash("dot11.probedssid.bssid"):
                    json_adapter_v2::json_encode_keyed<mac_addr>{}(os, f.second.rename, opts, bssid_);
                    break;
                case json_adapter_v2::consthash("dot11.probedssid.first_time"):
                    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, first_time_);
                    break;
                case json_adapter_v2::consthash("dot11.probedssid.last_time"):
                    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, last_time_);
                    break;
                case json_adapter_v2::consthash("dot11.probedssid.location"):
                    json_adapter_v2::group_fields(f.second.subfields, subgroup);
                    json_adapter_v2::json_encode_keyed<kis_tracked_location_v2>{}(os, f.second.rename, opts, location_, subgroup);
                    break;
                case json_adapter_v2::consthash("dot11.probedssid.mobility_id"):
                    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, dot11r_mobility_);
                    break;
                case json_adapter_v2::consthash("dot11.probedssid.mobility_domain_id"):
                    json_adapter_v2::json_encode_keyed<uint16_t>{}(os, f.second.rename, opts, dot11r_mobility_domain_);
                    break;
                case json_adapter_v2::consthash("dot11.probedssid.crypt_bitfield"):
                    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, crypt_set_);
                    break;
                case json_adapter_v2::consthash("dot11.probedssid.crypt_string"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, crypt_string_);
                    break;
                case json_adapter_v2::consthash("dot11.probedssid.wpa_mfp_required"):
                    json_adapter_v2::json_encode_keyed<bool>{}(os, f.second.rename, opts, wpa_mfp_required_);
                    break;
                case json_adapter_v2::consthash("dot11.probedssid.wpa_mfp_supported"):
                    json_adapter_v2::json_encode_keyed<bool>{}(os, f.second.rename, opts, wpa_mfp_supported_);
                    break;
                case json_adapter_v2::consthash("dot11.probedssid.ie_tag_list"):
                    json_adapter_v2::group_fields(f.second.subfields, subgroup);
                    json_adapter_v2::json_encode_keyed_array<ie_tag_list_iter_t_>{}(os, f.second.rename, opts,
                            ie_tag_list_.begin(), ie_tag_list_.end(), subgroup);
                    break;
                case json_adapter_v2::consthash("dot11.probedssid.wps_version"):
                    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, wps_version_);
                    break;
                case json_adapter_v2::consthash("dot11.probedssid.wps_state"):
                    json_adapter_v2::json_encode_keyed<uint32_t>{}(os, f.second.rename, opts, wps_state_);
                    break;
                case json_adapter_v2::consthash("dot11.probedssid.wps_config_methods"):
                    json_adapter_v2::json_encode_keyed<uint16_t>{}(os, f.second.rename, opts, wps_config_methods_);
                    break;
                case json_adapter_v2::consthash("dot11.probedssid.wps_manuf"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, wps_manuf_);
                    break;
                case json_adapter_v2::consthash("dot11.probedssid.wps_device_name"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, wps_device_name_);
                    break;
                case json_adapter_v2::consthash("dot11.probedssid.wps_model_name"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, wps_model_name_);
                    break;
                case json_adapter_v2::consthash("dot11.probedssid.wps_model_number"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, wps_model_number_);
                    break;
                case json_adapter_v2::consthash("dot11.probedssid.wps_serial_number"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, wps_serial_number_);
                    break;
                case json_adapter_v2::consthash("dot11.probedssid.wps_uuid_e"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, wps_uuid_e_);
                    break;
                default:
                    json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
            }
        }

        fmt::print(os, "}}");
        opts->next_key_comma = sv_comma;
    }

protected:
    std::string ssid_;
    uint8_t ssid_len_;

    mac_addr bssid_;

    uint64_t first_time_;
    uint64_t last_time_;

    kis_tracked_location_v2 location_;

    uint8_t dot11r_mobility_;
    uint16_t dot11r_mobility_domain_;

    uint64_t crypt_set_;
    std::string crypt_string_;

    uint8_t wpa_mfp_required_;
    uint8_t wpa_mfp_supported_;

    using ie_tag_list_iter_t_ = std::vector<dot11_tracked_ietag_v2>::iterator;
    std::vector<dot11_tracked_ietag_v2> ie_tag_list_;

    uint8_t wps_version_;
    uint32_t wps_state_;
    uint16_t wps_config_methods_;
    std::string wps_manuf_;
    std::string wps_device_name_;
    std::string wps_model_name_;
    std::string wps_model_number_;
    std::string wps_serial_number_;
    std::string wps_uuid_e_;
};

template<> struct json_adapter_v2::json_encode<dot11_probed_ssid_v2> {
     void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_probed_ssid_v2& e) {
         e.as_json(os, opts);
     }

     void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_probed_ssid_v2 *e) {
         e->as_json(os, opts);
     }

     void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_probed_ssid_v2& e,
             json_adapter_v2::field_group_map& fields) {
         e.filtered_as_json(os, opts, fields);
     }

     void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_probed_ssid_v2 *e,
             json_adapter_v2::field_group_map& fields) {
         e->filtered_as_json(os, opts, fields);
     }
};


class dot11_advertised_ssid_v2 : public json_adapter_v2::jsonable {
public:
    dot11_advertised_ssid_v2() :
    json_adapter_v2::jsonable() {
        reset();
    }

    virtual ~dot11_advertised_ssid_v2() { }

    void reset() {

    }

    const auto& ssid() const { return ssid_; }
    void set_ssid(const auto& v) { ssid_ = v; }

    auto ssid_len() const { return ssid_len_; }
    void set_ssid_len(auto v) { ssid_len_ = v; }

    auto ssid_hash() const { return ssid_hash_; }
    void set_ssid_hash(auto v) { ssid_hash_ = v; }

    auto ssid_cloaked() const { return ssid_cloaked_; }
    void set_ssid_cloaked(auto v) { ssid_cloaked_ = v; }

    auto ssid_crc32_hash() const { return ssid_crc32_hash_; }
    void set_ssid_crc32_hash(auto v) { ssid_crc32_hash_ = v; }

    const auto& owe_ssid() const { return owe_ssid_; }
    void set_owe_ssid(const auto& v) { owe_ssid_ = v; }

    auto owe_ssid_len() const { return owe_ssid_len_; }
    void set_owe_ssid_len(auto v) { owe_ssid_len_ = v; }

    const auto& owe_bssid() const { return owe_bssid_; }
    void set_owe_bssid(const auto& v) { owe_bssid_ = v; }

    auto ssid_beacon() const { return ssid_beacon_; }
    void set_ssid_beacon(auto v) { ssid_beacon_ = v; }

    auto ssid_probe_response() const { return ssid_probe_response_; }
    void set_ssid_probe_response(auto v) { ssid_probe_response_ = v; }

    const auto& channel() const { return channel_; }
    void set_channel(const auto& v) { channel_ = v; }

    const auto& ht_mode() const { return ht_mode_; }
    void set_ht_mode(const auto& v) { ht_mode_ = v; }

    auto ht_center_1() const { return ht_center_1_; }
    void set_ht_center_1(auto v) { ht_center_1_ = v; }

    auto ht_center_2() const { return ht_center_2_; }
    void set_ht_center_2(auto v) { ht_center_2_ = v; }

    auto channel_width() const { return channel_width_; }
    void set_channel_width(auto v) { channel_width_ = v; }

    const auto first_time() { return first_time_; }
    void set_first_time(auto time) { first_time_ = time; }
    void set_first_time_ifless(auto time) {
        if (time < first_time_) {
            first_time_ = time;
        }
    }

    const auto last_time() { return last_time_; }
    void set_last_time(auto time) { last_time_ = time; }
    void set_last_time_ifgreater(auto time) {
        if (last_time_ < time) {
            last_time_ = time;
        }
    }

    auto& location() const { return location_; }
    void set_location(const auto& v) { location_ = v; }

    const auto& beacon_info() const { return beacon_info_; }
    void set_beacon_info(const auto& v) { beacon_info_ = v; }

    auto crypt_set() const { return crypt_set_; }
    void set_crypt_set(auto v) { crypt_set_ = v; }

    const auto& crypt_string() const { return crypt_string_; }
    void set_crypt_string(const auto& v) { crypt_string_ = v; }

    auto wpa_mfp_required() const { return wpa_mfp_required_; }
    void set_wpa_mfp_required(auto v) { wpa_mfp_required_ = v; }

    auto wpa_mfp_supported() const { return wpa_mfp_supported_; }
    void set_wpa_mfp_supported(auto v) { wpa_mfp_supported_ = v; }

    auto maxrate() const { return maxrate_; }
    void set_maxrate(auto v) { maxrate_ = v; }

    auto beaconrate() const { return beaconrate_; }
    void set_beaconrate(auto v) { beaconrate_ = v; }

    auto beacons_seen() const { return beacons_seen_; }
    void set_beacons_seen(auto v) { beacons_seen_ = v; }
    void inc_beacons_seen(unsigned int seen, time_t time) {
        if (beacons_seen_sec_ != time) {
            beacons_seen_sec_ = time;
            beacons_seen_ = seen;
        } else {
            beacons_seen_ += seen;
        }
    }

    const auto& ie_tag_list() const { return ie_tag_list_; }
    void set_ie_tag_list(const auto& v) { ie_tag_list_ = v; }

    auto ie_tag_checksum() const { return ie_tag_checksum_; }
    void set_ie_tag_checksum(auto v) { ie_tag_checksum_ = v; }

    const auto& dot11d_country() const { return dot11d_country_; }
    void set_dot11d_country(const auto& v) { dot11d_country_ = v; }

    const auto& dot11d_vec() const { return dot11d_vec_; }
    void set_dot11d_vec(const auto& v) { dot11d_vec_ = v; }

    auto wps_version() const { return wps_version_; }
    void set_wps_version(auto v) { wps_version_ = v; }

    auto wps_state() const { return wps_state_; }
    void set_wps_state(auto v) { wps_state_ = v; }

    auto wps_config_methods() const { return wps_config_methods_; }
    void set_wps_config_methods(auto v) { wps_config_methods_ = v; }

    const auto& wps_manuf() const { return wps_manuf_; }
    void set_wps_manuf(const auto& v) { wps_manuf_ = v; }

    const auto& wps_device_name() const { return wps_device_name_; }
    void set_wps_device_name(const auto& v) { wps_device_name_ = v; }

    const auto& wps_model_name() const { return wps_model_name_; }
    void set_wps_model_name(const auto& v) { wps_model_name_ = v; }

    const auto& wps_uuid_e() const { return wps_uuid_e_; }
    void set_wps_uuid_e(const auto& v) { wps_uuid_e_ = v; }

    auto dot11r_mobility() const { return dot11r_mobility_; }
    void set_dot11r_mobility(auto v) { dot11r_mobility_ = v; }

    auto dot11r_mobility_domain() const { return dot11r_mobility_domain_; }
    void set_dot11r_mobility_domain(auto v) { dot11r_mobility_domain_ = v; }

    auto dot11e_qbss() const { return dot11e_qbss_; }
    void set_dot11e_qbss(auto v) { dot11e_qbss_ = v; }

    auto dot11e_qbss_stations() const { return dot11e_qbss_stations_; }
    void set_dot11e_qbss_stations(auto v) { dot11e_qbss_stations_ = v; }

    auto dot11e_qbss_load() const { return dot11e_qbss_load_; }
    void set_dot11e_qbss_load(auto v) { dot11e_qbss_load_ = v; }

    auto ccx_txpower() const { return ccx_txpower_; }
    void set_ccx_txpower(auto v) { ccx_txpower_ = v; }

    auto cisco_client_mfp() const { return cisco_client_mfp_; }
    void set_cisco_client_mfp(auto v) { cisco_client_mfp_ = v; }

    const auto& meshid() const { return meshid_; }
    void set_meshid(const auto& v) { meshid_ = v; }

    auto mesh_gateway() const { return mesh_gateway_; }
    void set_mesh_gateway(auto v) { mesh_gateway_ = v; }

    auto mesh_peerings() const { return mesh_peerings_; }
    void set_mesh_peerings(auto v) { mesh_peerings_ = v; }

    auto mesh_forwarding() const { return mesh_forwarding_; }
    void set_mesh_forwarding(auto v) { mesh_forwarding_ = v; }

    auto adv_tx_power() const { return adv_tx_power_; }
    void set_adv_tx_power(auto v) { adv_tx_power_ = v; }

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) override {
        json_adapter_v2::json_encode_keyed<kis_tracked_location_v2>{}(os, "dot11.advertisedssid.location", opts, location_);

        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.ssid", opts, ssid_);
        json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.advertisedssid.ssidlen", opts, ssid_len_);
        json_adapter_v2::json_encode_keyed<bool>{}(os, "dot11.advertisedssid.cloaked", opts, ssid_cloaked_);
        json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.advertisedssid.ssid_hash", opts, ssid_hash_);

        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.owe_ssid", opts, owe_ssid_);
        json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.advertisedssid.owe_ssid_len", opts, owe_ssid_len_);
        json_adapter_v2::json_encode_keyed<mac_addr>{}(os, "dot11.advertisedssid.owe_bssid", opts, owe_bssid_);

        json_adapter_v2::json_encode_keyed<bool>{}(os, "dot11.advertisedssid.beacon", opts, ssid_beacon_);
        json_adapter_v2::json_encode_keyed<bool>{}(os, "dot11.advertisedssid.probe_response", opts, ssid_probe_response_);

        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.channel", opts, channel_);
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.ht_mode", opts, ht_mode_);
        json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.advertisedssid.ht_center_1", opts, ht_center_1_);
        json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.advertisedssid.ht_center_2", opts, ht_center_2_);
        json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.advertisedssid.channel_width", opts, channel_width_);

        json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.advertisedssid.first_time", opts, first_time_);
        json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.advertisedssid.last_time", opts, last_time_);

        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.beacon_info", opts, beacon_info_);

        json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.advertisedssid.crypt_bitfield", opts, crypt_set_);
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.crypt_string", opts, crypt_string_);

        json_adapter_v2::json_encode_keyed<double>{}(os, "dot11.advertisedssid.maxrate", opts, maxrate_);

        json_adapter_v2::json_encode_keyed<uint32_t>{}(os, "dot11.advertisedssid.beaconrate", opts, beaconrate_);
        json_adapter_v2::json_encode_keyed<uint32_t>{}(os, "dot11.advertisedssid.beaconsec", opts, beacons_seen_sec_);

        json_adapter_v2::json_encode_keyed<uint32_t>{}(os, "dot11.advertisedssid.ietag_checksum", opts, ie_tag_checksum_);

        // encode as list of tag numbers
        json_adapter_v2::json_encode_keyed_array_custom<ie_tag_list_iter_t_>{}(os, "dot11.advertisedssid.ie_tag_list", opts,
                ie_tag_list_.begin(), ie_tag_list_.end(),
                [](std::ostream& os, json_adapter_v2::opts *opts, ie_tag_list_iter_t_ first) {
                    json_adapter_v2::json_encode<uint8_t>{}(os, opts, first->tag_number());
                });

        // encode as full data
        json_adapter_v2::json_encode_keyed_array<ie_tag_list_iter_t_>{}(os, "dot11.advertisedssid.ie_tag_content", opts,
                ie_tag_list_.begin(), ie_tag_list_.end());

        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.dot11d_country", opts, dot11d_country_);
        json_adapter_v2::json_encode_keyed_array<dot11d_vector_iter_t_>{}(os, "dot11.advertisedssid.dot11d_list", opts,
                dot11d_vec_.begin(), dot11d_vec_.end());

        json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.advertisedssid.wps_version", opts, wps_version_);
        json_adapter_v2::json_encode_keyed<uint32_t>{}(os, "dot11.advertisedssid.wps_state", opts, wps_state_);
        json_adapter_v2::json_encode_keyed<uint16_t>{}(os, "dot11.advertisedssid.wps_config_methods", opts, wps_config_methods_);
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.wps_manuf", opts, wps_manuf_);
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.wps_device_name", opts, wps_device_name_);
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.wps_model_name", opts, wps_model_name_);
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.wps_model_number", opts, wps_model_number_);
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.wps_serial_number", opts, wps_serial_number_);
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.wps_uuid_e", opts, wps_uuid_e_);

        json_adapter_v2::json_encode_keyed<bool>{}(os, "dot11.advertisedssid.dot11r_mobility", opts, dot11r_mobility_);
        json_adapter_v2::json_encode_keyed<uint16_t>{}(os, "dot11.advertisedssid.dot11r_mobility_domain_id", opts, dot11r_mobility_domain_);

        json_adapter_v2::json_encode_keyed<bool>{}(os, "dot11.advertisedssid.dot11e_qbss", opts, dot11e_qbss_);
        json_adapter_v2::json_encode_keyed<uint16_t>{}(os, "dot11.advertisedssid.dot11e_qbss_stations", opts, dot11e_qbss_stations_);
        json_adapter_v2::json_encode_keyed<double>{}(os, "dot11.advertisedssid.dot11e_qbss_channe_utilization", opts, dot11e_qbss_load_);

        json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.advertisedssid.ccx_txpower", opts, ccx_txpower_);
        json_adapter_v2::json_encode_keyed<bool>{}(os, "dot11.advertisedssid.cisco_client_mfp", opts, cisco_client_mfp_);

        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.advertisedssid.dot11s.meshid", opts, meshid_);
        json_adapter_v2::json_encode_keyed<bool>{}(os, "dot11.advertisedssid.dot11s.gateway", opts, mesh_gateway_);
        json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.advertisedssid.dot11s.num_peerings", opts, mesh_peerings_);
        json_adapter_v2::json_encode_keyed<bool>{}(os, "dot11.advertisedssid.dot11s.forwarding", opts, mesh_forwarding_);

        json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.advertisedssid.advertised_txpower", opts, adv_tx_power_);
    }

    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) override {
        if (fields.size() == 0) {
            return as_json(os, opts);
        }

        auto sv_comma = opts->next_key_comma;
        opts->next_key_comma = false;

        json_adapter_v2::field_group_map subgroup;

        fmt::print(os, "{{");
        for (const auto& f : fields) {
            switch (json_adapter_v2::consthash(f.first)) {
                case json_adapter_v2::consthash("dot11.advertisedssid.location"):
                    json_adapter_v2::group_fields(f.second.subfields, subgroup);
                    json_adapter_v2::json_encode_keyed<kis_tracked_location_v2>{}(os, f.second.rename, opts, location_, subgroup);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.ssid"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, ssid_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.ssidlen"):
                    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, ssid_len_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.cloaked"):
                    json_adapter_v2::json_encode_keyed<bool>{}(os, f.second.rename, opts, ssid_cloaked_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.ssid_hash"):
                    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, ssid_hash_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.owe_ssid"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, owe_ssid_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.owe_ssid_len"):
                    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, owe_ssid_len_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.owe_bssid"):
                    json_adapter_v2::json_encode_keyed<mac_addr>{}(os, f.second.rename, opts, owe_bssid_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.beacon"):
                    json_adapter_v2::json_encode_keyed<bool>{}(os, f.second.rename, opts, ssid_beacon_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.probe_response"):
                    json_adapter_v2::json_encode_keyed<bool>{}(os, f.second.rename, opts, ssid_probe_response_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.channel"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, channel_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.ht_mode"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, ht_mode_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.ht_center_1"):
                    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, ht_center_1_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.ht_center_2"):
                    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, ht_center_2_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.channel_width"):
                    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, channel_width_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.first_time"):
                    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, first_time_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.last_time"):
                    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, last_time_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.beacon_info"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, beacon_info_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.crypt_bitfield"):
                    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, crypt_set_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.crypt_string"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, crypt_string_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.maxrate"):
                    json_adapter_v2::json_encode_keyed<double>{}(os, f.second.rename, opts, maxrate_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.beaconrate"):
                    json_adapter_v2::json_encode_keyed<uint32_t>{}(os, f.second.rename, opts, beaconrate_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.beaconsec"):
                    json_adapter_v2::json_encode_keyed<uint32_t>{}(os, f.second.rename, opts, beacons_seen_sec_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.ietag_checksum"):
                    json_adapter_v2::json_encode_keyed<uint32_t>{}(os, f.second.rename, opts, ie_tag_checksum_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.ie_tag_list"):
                    json_adapter_v2::json_encode_keyed_array_custom<ie_tag_list_iter_t_>{}(os, f.second.rename, opts, ie_tag_list_.begin(), ie_tag_list_.end(), [](std::ostream& os, json_adapter_v2::opts *opts, ie_tag_list_iter_t_ first) { json_adapter_v2::json_encode<uint8_t>{}(os, opts, first->tag_number()); });
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.ie_tag_content"):
                    json_adapter_v2::group_fields(f.second.subfields, subgroup);
                    json_adapter_v2::json_encode_keyed_array<ie_tag_list_iter_t_>{}(os, f.second.rename, opts, ie_tag_list_.begin(), ie_tag_list_.end(), subgroup);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.dot11d_country"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, dot11d_country_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.dot11d_list"):
                    json_adapter_v2::json_encode_keyed_array<dot11d_vector_iter_t_>{}(os, f.second.rename, opts, dot11d_vec_.begin(), dot11d_vec_.end());
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.wps_version"):
                    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, wps_version_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.wps_state"):
                    json_adapter_v2::json_encode_keyed<uint32_t>{}(os, f.second.rename, opts, wps_state_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.wps_config_methods"):
                    json_adapter_v2::json_encode_keyed<uint16_t>{}(os, f.second.rename, opts, wps_config_methods_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.wps_manuf"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, wps_manuf_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.wps_device_name"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, wps_device_name_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.wps_model_name"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, wps_model_name_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.wps_model_number"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, wps_model_number_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.wps_serial_number"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, wps_serial_number_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.wps_uuid_e"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, wps_uuid_e_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.dot11r_mobility"):
                    json_adapter_v2::json_encode_keyed<bool>{}(os, f.second.rename, opts, dot11r_mobility_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.dot11r_mobility_domain_id"):
                    json_adapter_v2::json_encode_keyed<uint16_t>{}(os, f.second.rename, opts, dot11r_mobility_domain_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.dot11e_qbss"):
                    json_adapter_v2::json_encode_keyed<bool>{}(os, f.second.rename, opts, dot11e_qbss_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.dot11e_qbss_stations"):
                    json_adapter_v2::json_encode_keyed<uint16_t>{}(os, f.second.rename, opts, dot11e_qbss_stations_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.dot11e_qbss_channe_utilization"):
                    json_adapter_v2::json_encode_keyed<double>{}(os, f.second.rename, opts, dot11e_qbss_load_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.ccx_txpower"):
                    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, ccx_txpower_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.cisco_client_mfp"):
                    json_adapter_v2::json_encode_keyed<bool>{}(os, f.second.rename, opts, cisco_client_mfp_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.dot11s.meshid"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, meshid_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.dot11s.gateway"):
                    json_adapter_v2::json_encode_keyed<bool>{}(os, f.second.rename, opts, mesh_gateway_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.dot11s.num_peerings"):
                    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, mesh_peerings_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.dot11s.forwarding"):
                    json_adapter_v2::json_encode_keyed<bool>{}(os, f.second.rename, opts, mesh_forwarding_);
                    break;
                case json_adapter_v2::consthash("dot11.advertisedssid.advertised_txpower"):
                    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, adv_tx_power_);
                    break;
                default:
                    json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
            }
        }

        fmt::print(os, "}}");
        opts->next_key_comma = sv_comma;

    }

protected:
    kis_tracked_location_v2 location_;

    std::string ssid_;
    uint8_t ssid_len_;
    bool ssid_cloaked_;
    uint64_t ssid_hash_;
    uint32_t ssid_crc32_hash_;

    std::string owe_ssid_;
    uint8_t owe_ssid_len_;
    mac_addr owe_bssid_;

    bool ssid_beacon_;
    bool ssid_probe_response_;

    std::string channel_;
    std::string ht_mode_;
    uint64_t ht_center_1_;
    uint64_t ht_center_2_;
    uint64_t channel_width_;

    uint64_t first_time_;
    uint64_t last_time_;

    std::string beacon_info_;

    uint64_t crypt_set_;
    std::string crypt_string_;

    bool wpa_mfp_required_;
    bool wpa_mfp_supported_;

    double maxrate_;

    uint32_t beaconrate_;
    uint32_t beacons_seen_;
    time_t beacons_seen_sec_;

    using ie_tag_list_iter_t_ = std::vector<dot11_tracked_ietag_v2>::iterator;
    std::vector<dot11_tracked_ietag_v2> ie_tag_list_;
    uint32_t ie_tag_checksum_;

    std::string dot11d_country_;
    using dot11d_vector_iter_t_ = std::vector<dot11_11d_tracked_range_info_v2>::iterator;
    std::vector<dot11_11d_tracked_range_info_v2> dot11d_vec_;

    uint8_t wps_version_;
    uint32_t wps_state_;
    uint16_t wps_config_methods_;
    std::string wps_manuf_;
    std::string wps_device_name_;
    std::string wps_model_name_;
    std::string wps_model_number_;
    std::string wps_serial_number_;
    std::string wps_uuid_e_;

    bool dot11r_mobility_;
    uint16_t dot11r_mobility_domain_;

    bool dot11e_qbss_;
    uint16_t dot11e_qbss_stations_;
    double dot11e_qbss_load_;

    uint8_t ccx_txpower_;
    bool cisco_client_mfp_;

    std::string meshid_;
    bool mesh_gateway_;
    uint8_t mesh_peerings_;
    bool mesh_forwarding_;

    uint8_t adv_tx_power_;
};

template<> struct json_adapter_v2::json_encode<dot11_advertised_ssid_v2> {
     void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_advertised_ssid_v2& e) {
         e.as_json(os, opts);
     }

     void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_advertised_ssid_v2 *e) {
         e->as_json(os, opts);
     }

     void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_advertised_ssid_v2& e,
             json_adapter_v2::field_group_map& fields) {
         e.filtered_as_json(os, opts, fields);
     }

     void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_advertised_ssid_v2 *e,
             json_adapter_v2::field_group_map& fields) {
         e->filtered_as_json(os, opts, fields);
     }
};


#endif /* __PHY_80211_COMPONENTS_V2__ */

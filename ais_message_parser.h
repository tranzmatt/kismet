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

#ifndef __AIS_MESSAGE_PARSER_H__
#define __AIS_MESSAGE_PARSER_H__

#include "config.h"
#include <string>
#include <vector>
#include <cstdint>
#include <memory> // For std::unique_ptr
#include <nlohmann/json.hpp>

namespace AISParser {

class AISMessage {
protected:
    std::vector<bool> payload_bits;
    int message_type;

    uint64_t get_uint(size_t start_bit, size_t num_bits) const;
    int64_t get_int(size_t start_bit, size_t num_bits) const;
    std::string get_string(size_t start_bit, size_t num_chars) const;

public:
    AISMessage(const std::string& encoded_payload, int num_fill_bits);
    virtual ~AISMessage() = default;

    int get_message_type() const { return message_type; }
    virtual void parse(nlohmann::json& out_json) const = 0;

    static int decode_6bit_ascii(char c);
};

class AISMessageType123 : public AISMessage {
public:
    AISMessageType123(const std::string& encoded_payload, int num_fill_bits);
    void parse(nlohmann::json& out_json) const override;
};

class AISMessageType5 : public AISMessage {
public:
    AISMessageType5(const std::string& encoded_payload, int num_fill_bits);
    void parse(nlohmann::json& out_json) const override;
};

// Factory Function
std::unique_ptr<AISMessage> create_ais_message(int message_type, const std::string& encoded_payload, int num_fill_bits);

} // namespace AISParser

#endif // __AIS_MESSAGE_PARSER_H__

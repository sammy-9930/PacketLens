#include "sniffer/capture/hex_replay/hex_packet_source.h"

#include <istream>
#include <stdexcept>
#include <string>

namespace {

// Convert an ASCII hex digit to its value or return -1 for an invalid byte.
int hex_digit(char digit) {
    if (digit >= '0' && digit <= '9') return digit - '0';
    if (digit >= 'a' && digit <= 'f') return digit - 'a' + 10;
    if (digit >= 'A' && digit <= 'F') return digit - 'A' + 10;
    return -1;
}

}  // namespace

bool HexPacketSource::next(Packet& packet) {
    // One contiguous hex string per IP packet. Bound each record before decoding.
    constexpr std::streamsize max_hex_length = 2 * 65575;
    char line[max_hex_length + 2];  // Allow a carriage return and string terminator.
    while (input_.getline(line, sizeof(line))) {
        ++line_number_;
        auto length = input_.gcount();
        if (!input_.eof()) --length;  // gcount includes a consumed newline.
        if (length > 0 && line[length - 1] == '\r') --length;
        if (length == 0) continue;

        const auto invalid = [this] {
            return std::runtime_error("invalid hex IP packet on line " +
                                      std::to_string(line_number_));
        };
        if (length > max_hex_length || length % 2 != 0) throw invalid();
        packet.bytes.resize(static_cast<std::size_t>(length / 2));
        for (std::streamsize i = 0; i < length; i += 2) {
            const int high = hex_digit(line[i]);
            const int low = hex_digit(line[i + 1]);
            if (high < 0 || low < 0) throw invalid();
            packet.bytes[i / 2] = static_cast<std::uint8_t>(high * 16 + low);
        }
        switch (packet.bytes.front() >> 4) {
        case 4: packet.ether_type = 0x0800; break;
        case 6: packet.ether_type = 0x86dd; break;
        default: throw invalid();
        }
        return true;
    }
    if (input_.bad() || !input_.eof()) {
        throw std::runtime_error("cannot read hex IP packet on line " +
                                 std::to_string(line_number_ + 1));
    }
    return false;
}

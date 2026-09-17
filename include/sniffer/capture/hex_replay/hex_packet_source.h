#ifndef SNIFFER_HEX_PACKET_SOURCE_H
#define SNIFFER_HEX_PACKET_SOURCE_H

#include "sniffer/packet_source.h"

#include <cstddef>
#include <iosfwd>

class HexPacketSource final : public PacketSource {
public:
    // Borrow a stream containing one hex-encoded IP packet per nonempty line.
    explicit HexPacketSource(std::istream& input) : input_(input) {}
    // Decode the next hex record. Return false at EOF and throw on malformed input.
    bool next(Packet& packet) override;

private:
    std::istream& input_;
    std::size_t line_number_ = 0;
};

#endif

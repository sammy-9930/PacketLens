#ifndef SNIFFER_PACKET_SOURCE_H
#define SNIFFER_PACKET_SOURCE_H

#include <cstdint>
#include <vector>

// The source supplies a host-order EtherType and bytes starting at the network-layer header.
struct Packet {
    std::uint16_t ether_type;
    std::vector<std::uint8_t> bytes;
};

class PacketSource {
public:
    // Allow capture backends to release their resources through the base interface.
    virtual ~PacketSource() = default;
    // Fill packet with the next capture. Return false when the source ends.
    virtual bool next(Packet& packet) = 0;
};

#endif

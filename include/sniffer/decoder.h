#ifndef SNIFFER_DECODER_H
#define SNIFFER_DECODER_H

#include "sniffer/packet_source.h"

#include <string>

enum class IpVersion { v4, v6 };

struct PacketMetadata {
    IpVersion version;
    std::string source;
    std::string destination;
    unsigned protocol;
    unsigned length;
};

class PacketDecoder {
public:
    // Allow decoder implementations to be destroyed through the base interface.
    virtual ~PacketDecoder() = default;
    // Return true and populate metadata for a supported, well-formed IP packet.
    // Implementations used by multiple workers must allow concurrent decode calls.
    virtual bool decode(const Packet& packet, PacketMetadata& metadata) const = 0;
};

class IpPacketDecoder final : public PacketDecoder {
public:
    // Validate the IP header and extract addresses, protocol number, and IP length.
    bool decode(const Packet& packet, PacketMetadata& metadata) const override;
};

// Decode a packet with the standard IP decoder.
bool decode_packet(const Packet& packet, PacketMetadata& metadata);

#endif

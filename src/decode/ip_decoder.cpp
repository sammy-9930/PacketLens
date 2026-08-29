#include "sniffer/decoder.h"

#include <arpa/inet.h>

namespace {

// Read a big-endian 16-bit value at an offset the caller has validated.
unsigned read_u16(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    return (static_cast<unsigned>(bytes[offset]) << 8) | bytes[offset + 1];
}

// Walk IPv6 extension headers within the declared packet length to find the protocol.
bool ipv6_protocol(const std::vector<std::uint8_t>& bytes, unsigned length,
                   unsigned& protocol) {
    // IPv6 extension headers follow the fixed 40-byte base header.
    unsigned offset = 40;
    protocol = bytes[6];
    while (protocol == 0 || protocol == 43 || protocol == 44 ||
           protocol == 51 || protocol == 60) {
        // Use the IP packet length as the boundary even if the capture includes padding.
        if (length - offset < 8) {
            return false;
        }
        const unsigned next = bytes[offset];
        unsigned extension_length;
        if (protocol == 44) {
            // Non-initial fragments do not contain the rest of the header chain.
            if ((read_u16(bytes, offset + 2) & 0xfff8) != 0) {
                protocol = next;
                return true;
            }
            extension_length = 8;
        } else if (protocol == 51) {
            // Authentication Header length is measured in 32-bit words minus two.
            extension_length = (bytes[offset + 1] + 2U) * 4U;
            if (extension_length < 12) {
                return false;
            }
        } else {
            extension_length = (bytes[offset + 1] + 1U) * 8U;
        }
        if (extension_length > length - offset) {
            return false;
        }
        offset += extension_length;
        protocol = next;
    }
    return true;
}

}  // namespace

bool IpPacketDecoder::decode(const Packet& packet, PacketMetadata& metadata) const {
    const auto& bytes = packet.bytes;
    int family;
    unsigned source_offset;
    unsigned destination_offset;
    unsigned protocol;
    unsigned length;

    switch (packet.ether_type) {
    case 0x0800: {
        if (bytes.size() < 20 || bytes[0] >> 4 != 4) {
            return false;
        }
        const unsigned header_length = (bytes[0] & 0xf) * 4;
        length = read_u16(bytes, 2);
        if (header_length < 20 || length < header_length || length > bytes.size()) {
            return false;
        }
        family = AF_INET;
        source_offset = 12;
        destination_offset = 16;
        protocol = bytes[9];
        break;
    }
    case 0x86dd:
        if (bytes.size() < 40 || bytes[0] >> 4 != 6) {
            return false;
        }
        length = 40 + read_u16(bytes, 4);
        if (length > bytes.size()) {
            return false;
        }
        family = AF_INET6;
        source_offset = 8;
        destination_offset = 24;
        if (!ipv6_protocol(bytes, length, protocol)) {
            return false;
        }
        break;
    default:
        return false;
    }

    char source[INET6_ADDRSTRLEN];
    char destination[INET6_ADDRSTRLEN];
    if (!inet_ntop(family, bytes.data() + source_offset, source, sizeof(source)) ||
        !inet_ntop(family, bytes.data() + destination_offset, destination,
                   sizeof(destination))) {
        return false;
    }
    metadata = {family == AF_INET ? IpVersion::v4 : IpVersion::v6,
                source, destination, protocol, length};
    return true;
}

bool decode_packet(const Packet& packet, PacketMetadata& metadata) {
    return IpPacketDecoder{}.decode(packet, metadata);
}

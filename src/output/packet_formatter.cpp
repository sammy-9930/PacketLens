#include "sniffer/sniffer.h"

#include <ostream>

const char* protocol_name(unsigned protocol) {
    switch (protocol) {
    case 1: return "ICMP";
    case 2: return "IGMP";
    case 6: return "TCP";
    case 17: return "UDP";
    case 50: return "ESP";
    case 58: return "ICMPv6";
    case 59: return "No Next Header";
    case 132: return "SCTP";
    default: return "Unknown";
    }
}

bool StreamPacketSink::ready() const {
    return static_cast<bool>(output_);
}

void StreamPacketSink::write(const PacketMetadata& metadata) {
    output_ << (metadata.version == IpVersion::v4 ? "IPv4 " : "IPv6 ")
           << metadata.source << " -> " << metadata.destination
           << " protocol=" << protocol_name(metadata.protocol)
           << '(' << metadata.protocol << ") bytes=" << metadata.length << '\n';
}

bool print_packet(const Packet& packet, std::ostream& output) {
    PacketMetadata metadata{};
    if (!decode_packet(packet, metadata)) {
        return false;
    }
    StreamPacketSink(output).write(metadata);
    return true;
}

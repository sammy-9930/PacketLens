#ifndef SNIFFER_PCAP_PACKET_SOURCE_H
#define SNIFFER_PCAP_PACKET_SOURCE_H

#include "sniffer/packet_source.h"

#include <fstream>
#include <string>

class PcapPacketSource final : public PacketSource {
public:
    // Open a classic Ethernet PCAP and validate its file header.
    explicit PcapPacketSource(const std::string& path);
    // Read the next record and strip Ethernet framing. Return false at clean EOF.
    bool next(Packet& packet) override;

private:
    // Read a field using the byte order declared by the PCAP file.
    unsigned read_unsigned(const unsigned char* bytes, unsigned width) const;

    std::ifstream input_;
    std::string path_;
    bool little_endian_ = false;
    unsigned snap_length_ = 0;
    std::vector<std::uint8_t> frame_;
};

#endif

#include "sniffer/capture/pcap_replay/pcap_packet_source.h"
#include "sniffer/capture/common/ethernet_frame.h"

#include <stdexcept>

PcapPacketSource::PcapPacketSource(const std::string& path)
    : input_(path, std::ios::binary), path_(path) {
    if (!input_) {
        throw std::runtime_error(path + ": cannot open PCAP file");
    }
    unsigned char header[24];
    if (!input_.read(reinterpret_cast<char*>(header), sizeof(header))) {
        throw std::runtime_error(path + ": incomplete PCAP header");
    }
    // Read the magic as big-endian first so both byte orders can be identified.
    const unsigned magic = read_unsigned(header, 4);
    little_endian_ = magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1;
    if (!little_endian_ && magic != 0xa1b2c3d4 && magic != 0xa1b23c4d) {
        throw std::runtime_error(path + ": expected classic PCAP");
    }
    if (read_unsigned(header + 4, 2) != 2 || read_unsigned(header + 6, 2) != 4 ||
        read_unsigned(header + 20, 4) != 1) {
        throw std::runtime_error(path + ": expected PCAP 2.4 with Ethernet link type");
    }
    snap_length_ = read_unsigned(header + 16, 4);
}

unsigned PcapPacketSource::read_unsigned(const unsigned char* bytes, unsigned width) const {
    unsigned value = 0;
    for (unsigned i = 0; i < width; ++i) {
        value = (value << 8) | bytes[little_endian_ ? width - i - 1 : i];
    }
    return value;
}

bool PcapPacketSource::next(Packet& packet) {
    unsigned char record[16];
    if (!input_.read(reinterpret_cast<char*>(record), sizeof(record))) {
        if (input_.eof() && !input_.bad() && input_.gcount() == 0) {
            return false;
        }
        throw std::runtime_error(path_ + ": incomplete PCAP record header");
    }
    const auto captured = read_unsigned(record + 8, 4);
    const auto original = read_unsigned(record + 12, 4);
    // Allow jumbo frames while bounding allocation from untrusted record lengths.
    if (captured > snap_length_ || captured > original || captured > 1024 * 1024) {
        throw std::runtime_error(path_ + ": invalid or oversized PCAP record");
    }
    frame_.resize(captured);
    if (captured && !input_.read(reinterpret_cast<char*>(frame_.data()), captured)) {
        throw std::runtime_error(path_ + ": incomplete PCAP frame");
    }
    if (!decode_ethernet_frame(frame_.data(), frame_.size(), packet)) {
        // Keep malformed frames visible in the pipeline's skipped count.
        packet.ether_type = 0;
        packet.bytes.clear();
    }
    return true;
}

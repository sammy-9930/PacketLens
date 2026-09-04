#include "sniffer/capture/common/ethernet_frame.h"

bool decode_ethernet_frame(const std::uint8_t* frame, std::size_t size, Packet& packet) {
    // Ethernet II starts with two six-byte addresses and a two-byte EtherType.
    std::size_t payload = 14;
    if (size < payload) return false;

    auto ether_type = static_cast<std::uint16_t>((frame[12] << 8) | frame[13]);
    while (ether_type == 0x8100 || ether_type == 0x88a8) {
        // A VLAN tag adds two control bytes followed by the inner EtherType.
        if (size - payload < 4) return false;
        ether_type = static_cast<std::uint16_t>((frame[payload + 2] << 8) | frame[payload + 3]);
        payload += 4;
    }

    if (ether_type < 0x0600) return false;  // IEEE 802.3 length field.
    packet.ether_type = ether_type;
    packet.bytes.assign(frame + payload, frame + size);
    return true;
}

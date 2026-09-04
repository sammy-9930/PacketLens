#ifndef SNIFFER_ETHERNET_FRAME_H
#define SNIFFER_ETHERNET_FRAME_H

#include "sniffer/packet_source.h"

#include <cstddef>

// Strip Ethernet II and any VLAN tags to produce a network-layer packet.
bool decode_ethernet_frame(const std::uint8_t* frame, std::size_t size, Packet& packet);

#endif

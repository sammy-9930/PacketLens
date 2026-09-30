#ifndef SNIFFER_LINUX_PACKET_SOURCE_H
#define SNIFFER_LINUX_PACKET_SOURCE_H

#include "sniffer/packet_source.h"

#include <atomic>

class LinuxPacketSource final : public PacketSource {
public:
    enum class Mode { cooked, raw_ethernet };

    // Open and bind a Linux packet socket to the requested interface and mode.
    explicit LinuxPacketSource(const char* interface, Mode mode = Mode::cooked);
    // Close the owned packet socket.
    ~LinuxPacketSource() override;

    // Keep socket ownership exclusive by disabling copying.
    LinuxPacketSource(const LinuxPacketSource&) = delete;
    LinuxPacketSource& operator=(const LinuxPacketSource&) = delete;

    // Receive the next supported frame and normalize it to a network-layer packet.
    bool next(Packet& packet) override;
    // Borrow a stop flag and use timed polling so idle reads can observe it.
    void stop_on(const std::atomic<bool>& flag) { stop_flag_ = &flag; }
    // Linux resets these counters when queried.
    unsigned kernel_drops() const;

private:
    const Mode mode_;
    int socket_;
    const std::atomic<bool>* stop_flag_ = nullptr;
    std::uint8_t buffer_[65575 + 14 + 8];  // Full IPv6 packet plus Ethernet header and two VLAN tags.
};

#endif

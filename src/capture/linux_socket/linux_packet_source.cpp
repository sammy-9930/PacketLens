#include "sniffer/capture/linux_socket/linux_packet_source.h"
#include "sniffer/capture/common/ethernet_frame.h"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <system_error>

LinuxPacketSource::LinuxPacketSource(const char* interface, Mode mode) : mode_(mode) {
    const unsigned index = if_nametoindex(interface);
    if (!index) {
        throw std::system_error(errno, std::generic_category(), interface);
    }
    const auto protocol = htons(ETH_P_ALL);
    // SOCK_DGRAM strips the link-layer header. SOCK_RAW retains it.
    // Protocol zero defers capture until bind.
    const int socket_type = mode_ == Mode::cooked ? SOCK_DGRAM : SOCK_RAW;
    socket_ = socket(AF_PACKET, socket_type | SOCK_CLOEXEC, 0);
    if (socket_ < 0) {
        throw std::system_error(errno, std::generic_category(), "packet socket");
    }

    sockaddr_ll address{};
    address.sll_family = AF_PACKET;
    address.sll_protocol = protocol;
    address.sll_ifindex = static_cast<int>(index);
    if (bind(socket_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
        const int error = errno;
        close(socket_);
        throw std::system_error(error, std::generic_category(), "bind packet socket");
    }
}

LinuxPacketSource::~LinuxPacketSource() {
    close(socket_);
}

bool LinuxPacketSource::next(Packet& packet) {
    sockaddr_ll address{};
    while (!stop_flag_ || !stop_flag_->load(std::memory_order_relaxed)) {
        if (stop_flag_) {
            // Bound the wait so an interrupt delivered to either thread stops capture.
            pollfd descriptor{socket_, POLLIN, 0};
            const int ready = poll(&descriptor, 1, 250);
            if (ready == 0 || (ready < 0 && errno == EINTR)) continue;
            if (ready < 0) {
                throw std::system_error(errno, std::generic_category(), "poll packet socket");
            }
            if (stop_flag_->load(std::memory_order_relaxed)) return false;
        }
        // recvfrom updates the address length, so reset it before each attempt.
        socklen_t address_length = sizeof(address);
        const auto size = recvfrom(socket_, buffer_, sizeof(buffer_), MSG_TRUNC | (stop_flag_ ? MSG_DONTWAIT : 0),
                                   reinterpret_cast<sockaddr*>(&address), &address_length);
        if (size >= 0) {
            // MSG_TRUNC reports the original length so a partial capture can be skipped.
            if (static_cast<std::size_t>(size) > sizeof(buffer_)) continue;
            if (mode_ == Mode::cooked) {
                packet.ether_type = ntohs(address.sll_protocol);
                packet.bytes.assign(buffer_, buffer_ + size);
                return true;
            }
            // Normalize Ethernet II frames before passing bytes to the IP decoder.
            if (address.sll_hatype != ARPHRD_ETHER && address.sll_hatype != ARPHRD_LOOPBACK) {
                continue;
            }
            if (!decode_ethernet_frame(buffer_, static_cast<std::size_t>(size), packet)) {
                continue;
            }
            return true;
        }
        if (errno != EINTR && !(stop_flag_ && (errno == EAGAIN || errno == EWOULDBLOCK))) {
            throw std::system_error(errno, std::generic_category(), "receive packet");
        }
    }
    return false;
}

unsigned LinuxPacketSource::kernel_drops() const {
    tpacket_stats stats{};
    socklen_t length = sizeof(stats);
    if (getsockopt(socket_, SOL_PACKET, PACKET_STATISTICS, &stats, &length) < 0) {
        throw std::system_error(errno, std::generic_category(), "read packet socket statistics");
    }
    return stats.tp_drops;
}

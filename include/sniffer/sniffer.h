#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include "sniffer/decoder.h"
#include "sniffer/packet_sink.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iosfwd>

// Decode and format one supported IP packet. Return false when decoding rejects it.
bool print_packet(const Packet& packet, std::ostream& output);
struct CaptureMetrics {
    std::uint64_t packets_read = 0;
    std::uint64_t decoded = 0;
    std::uint64_t decoded_ip_bytes = 0;
    std::uint64_t skipped = 0;
    std::uint64_t queue_high_water = 0;
    std::uint64_t queue_waits = 0;
};

// Read, decode, and write packets synchronously while the sink is ready.
CaptureMetrics run(PacketSource& source, const PacketDecoder& decoder, PacketSink& sink);
// Run the synchronous pipeline with the IP decoder and a stream sink.
void run(PacketSource& source, std::ostream& output);

struct ProtocolMetrics {
    std::uint64_t decoded = 0;
    std::uint64_t skipped = 0;
    std::uint64_t decoded_ip_bytes = 0;
    std::array<std::uint64_t, 256> protocols{};
};

// The callback receives interval totals, actual elapsed seconds, and a final marker.
using MetricsReporter = std::function<void(const ProtocolMetrics&, double, bool)>;

constexpr std::size_t default_worker_queue_capacity = 64;

// Zero workers decodes on the receiving thread. Reporting uses its own timer thread.
CaptureMetrics run_metrics(PacketSource& source, const PacketDecoder& decoder,
                           unsigned workers, const MetricsReporter& reporter,
                           std::size_t queue_capacity = default_worker_queue_capacity);

// Count CPUs allowed by Linux affinity, falling back to hardware concurrency.
unsigned available_capture_cpus();

// Keep reading on the caller thread and process queued packets on worker threads.
// Results from multiple workers can be written out of capture order.
// A source read already in progress must return before this function can finish.
CaptureMetrics run_threaded(PacketSource& source, const PacketDecoder& decoder, PacketSink& sink,
                            unsigned workers = 1,
                            std::size_t queue_capacity = default_worker_queue_capacity);

#endif

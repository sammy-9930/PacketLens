#include "sniffer/sniffer.h"

#include <benchmark/benchmark.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <ostream>
#include <streambuf>
#include <vector>

namespace {

constexpr std::uint64_t packets_per_run = 16384;

class ReplaySource final : public PacketSource {
public:
    // Return one synthetic packet until the fixed iteration workload is exhausted.
    bool next(Packet& packet) override {
        if (remaining_ == 0) {
            return false;
        }
        --remaining_;
        packet = sample_;
        return true;
    }

private:
    std::uint64_t remaining_ = packets_per_run;
    const Packet sample_{0x0800, {0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17,
                                  0, 0, 192, 0, 2, 1, 198, 51, 100, 2}};
};

class CountingSink final : public PacketSink {
public:
    // Keep the in-memory counting sink available for the entire run.
    bool ready() const override { return true; }
    // Track IP bytes delivered to the counting sink.
    void write(const PacketMetadata& metadata) override {
        bytes += metadata.length;
    }

    std::uint64_t bytes = 0;
};

// Keep text formatting in the measurement without involving a terminal or disk.
class DiscardBuffer final : public std::streambuf {
protected:
    // Accept a block of formatted output without storing it.
    std::streamsize xsputn(const char*, std::streamsize count) override { return count; }
    // Accept a single character without storing it.
    int_type overflow(int_type value) override { return traits_type::not_eof(value); }
};

enum class OutputMode { counting, per_packet, metrics };

// Run the same input through each reporting strategy and validate the resulting totals.
void measure_capture(benchmark::State& state, OutputMode mode,
                     std::size_t capacity = default_worker_queue_capacity) {
    const auto cpus = static_cast<unsigned>(state.range(0));
    const IpPacketDecoder decoder;
    std::uint64_t waits = 0;
    std::uint64_t decoded_bytes = 0;
    for (auto iteration : state) {
        (void)iteration;
        ReplaySource source;
        CountingSink sink;
        CaptureMetrics metrics;
        std::uint64_t published_packets = 0;
        std::uint64_t published_bytes = 0;
        if (mode == OutputMode::metrics) {
            metrics = run_metrics(source, decoder, cpus - 1,
                [&](const ProtocolMetrics& interval, double, bool) {
                    published_packets += interval.protocols[17];
                    published_bytes += interval.decoded_ip_bytes;
                }, capacity);
        } else if (mode == OutputMode::per_packet) {
            DiscardBuffer buffer;
            std::ostream stream(&buffer);
            StreamPacketSink output(stream);
            metrics = cpus == 1 ? run(source, decoder, output)
                                : run_threaded(source, decoder, output, cpus - 1);
            published_packets = metrics.decoded;
            published_bytes = metrics.decoded_ip_bytes;
        } else {
            metrics = cpus == 1 ? run(source, decoder, sink)
                                : run_threaded(source, decoder, sink, cpus - 1);
            published_packets = metrics.decoded;
            published_bytes = sink.bytes;
        }
        if (metrics.decoded != packets_per_run || metrics.decoded_ip_bytes != packets_per_run * 20 ||
            published_packets != metrics.decoded || published_bytes != metrics.decoded_ip_bytes) {
            state.SkipWithError("incomplete replay");
            return;
        }
        waits += metrics.queue_waits;
        decoded_bytes += metrics.decoded_ip_bytes;
    }
    state.SetBytesProcessed(decoded_bytes);
    state.SetItemsProcessed(state.iterations() * packets_per_run);
    state.counters["queue_waits"] = benchmark::Counter(waits, benchmark::Counter::kAvgIterations);
}

// Measure the pipeline with an in-memory byte counter.
void capture(benchmark::State& state) {
    measure_capture(state, OutputMode::counting);
}

// Measure the pipeline with per-packet text formatting.
void capture_per_packet(benchmark::State& state) {
    measure_capture(state, OutputMode::per_packet);
}

// Measure the pipeline with periodic aggregated counters.
void capture_metrics_only(benchmark::State& state) {
    measure_capture(state, OutputMode::metrics);
}

// Sweep input capacities using the normal metrics pipeline.
void capture_queue_capacity(benchmark::State& state) {
    measure_capture(state, OutputMode::metrics, static_cast<std::size_t>(state.range(1)));
}

using Clock = std::chrono::steady_clock;

class TimestampedSource final : public PacketSource {
public:
    explicit TimestampedSource(std::vector<Clock::time_point>& produced) : produced_(produced) {}

    bool next(Packet& packet) override {
        if (!source_.next(packet)) {
            return false;
        }
        // Use the IPv4 identification field to associate each packet with its timestamp.
        packet.bytes[4] = static_cast<std::uint8_t>(index_ >> 8);
        packet.bytes[5] = static_cast<std::uint8_t>(index_);
        produced_[index_++] = Clock::now();
        return true;
    }

private:
    ReplaySource source_;
    std::vector<Clock::time_point>& produced_;
    std::size_t index_ = 0;
};

class TimestampedDecoder final : public PacketDecoder {
public:
    TimestampedDecoder(const std::vector<Clock::time_point>& produced, std::vector<double>& delays)
        : produced_(produced), delays_(delays) {}

    bool decode(const Packet& packet, PacketMetadata& metadata) const override {
        const auto began = Clock::now();
        const std::size_t index = (static_cast<std::size_t>(packet.bytes[4]) << 8) | packet.bytes[5];
        // Queue ownership transfer makes the producer timestamp visible to this decoder.
        delays_[index] = std::chrono::duration<double, std::micro>(began - produced_[index]).count();
        return decoder_.decode(packet, metadata);
    }

private:
    const std::vector<Clock::time_point>& produced_;
    std::vector<double>& delays_;
    IpPacketDecoder decoder_;
};

// Run a separate instrumented replay to avoid adding clock reads to throughput measurements.
void queue_handoff_latency(benchmark::State& state) {
    const auto workers = static_cast<unsigned>(state.range(0) - 1);
    const auto capacity = static_cast<std::size_t>(state.range(1));
    std::vector<Clock::time_point> produced(packets_per_run);
    std::vector<double> delays(packets_per_run);
    constexpr auto percentile_index = (packets_per_run * 95 + 99) / 100 - 1;
    double p95_total = 0;
    for (auto iteration : state) {
        (void)iteration;
        TimestampedSource source(produced);
        TimestampedDecoder decoder(produced, delays);
        const auto metrics = run_metrics(source, decoder, workers,
            [](const ProtocolMetrics&, double, bool) {}, capacity);
        if (metrics.decoded != packets_per_run) {
            state.SkipWithError("incomplete latency replay");
            return;
        }
        state.PauseTiming();
        std::nth_element(delays.begin(), delays.begin() + percentile_index, delays.end());
        p95_total += delays[percentile_index];
        state.ResumeTiming();
    }
    state.counters["handoff_p95_us"] = benchmark::Counter(p95_total, benchmark::Counter::kAvgIterations);
}

// Keep three decode workers for every capacity so only the queue limit changes.
void queue_capacities(benchmark::internal::Benchmark* benchmark) {
    benchmark->ArgNames({"cpus", "capacity"})->Args({4, 64})->Args({4, 256})->Args({4, 1024});
}

// Benchmark powers of two and the maximum available capture thread count.
void thread_counts(benchmark::internal::Benchmark* benchmark) {
    const auto available = available_capture_cpus();
    for (unsigned count = 1; count < available; count *= 2) {
        benchmark->Arg(count);
        if (count > available / 2) {
            break;
        }
    }
    benchmark->Arg(available);
}

BENCHMARK(capture)->ArgName("cpus")->Apply(thread_counts)->MeasureProcessCPUTime()->UseRealTime();
BENCHMARK(capture_per_packet)
    ->ArgName("cpus")->Apply(thread_counts)->MeasureProcessCPUTime()->UseRealTime();
BENCHMARK(capture_metrics_only)
    ->ArgName("cpus")->Apply(thread_counts)->MeasureProcessCPUTime()->UseRealTime();

BENCHMARK(capture_queue_capacity)->Apply(queue_capacities)->MeasureProcessCPUTime()->UseRealTime();
BENCHMARK(queue_handoff_latency)->Apply(queue_capacities)->UseRealTime();

}  // namespace

BENCHMARK_MAIN();

#include "sniffer/capture/hex_replay/hex_packet_source.h"
#include "sniffer/capture/linux_socket/linux_packet_source.h"
#include "sniffer/capture/pcap_replay/pcap_packet_source.h"
#include "sniffer/config.h"
#include "sniffer/sniffer.h"

#include <atomic>
#include <csignal>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

namespace {

static_assert(ATOMIC_BOOL_LOCK_FREE == 2, "capture interruption requires lock-free atomics");
std::atomic<bool> interrupted{false};

// Set the lock-free stop flag from SIGINT so the live source can exit its read loop.
void interrupt_capture(int) {
    interrupted.store(true, std::memory_order_relaxed);
}

// Write one JSON interval with protocol-number keys for dashboard import.
void report_interval(const ProtocolMetrics& interval, double seconds, bool final) {
    std::cout << "{\"seconds\":" << seconds
              << ",\"decoded\":" << interval.decoded
              << ",\"skipped\":" << interval.skipped
              << ",\"bytes\":" << interval.decoded_ip_bytes
              << ",\"final\":" << (final ? "true" : "false")
              << ",\"protocols\":{";
    bool first = true;
    for (std::size_t protocol = 0; protocol < interval.protocols.size(); ++protocol) {
        if (interval.protocols[protocol] == 0) {
            continue;
        }
        if (!first) {
            std::cout << ',';
        }
        std::cout << '"' << protocol << "\":" << interval.protocols[protocol];
        first = false;
    }
    std::cout << "}}\n" << std::flush;
}

class ConsoleReport {
public:
    // Print interval rates and protocol counts, plus the cumulative packet total.
    void operator()(const ProtocolMetrics& interval, double seconds, bool final) {
        packets_ += interval.decoded;
        bytes_ += interval.decoded_ip_bytes;
        seconds_ += seconds;
        const auto rate = [](double count, double elapsed) {
            return elapsed > 0 ? count / elapsed : 0;
        };

        std::cout << std::fixed << std::setprecision(2)
                  << (final ? "Final | " : "")
                  << seconds_ << " s | "
                  << rate(interval.decoded, seconds) << " packets/s | "
                  << rate(interval.decoded_ip_bytes * 8.0 / 1e6, seconds) << " Mb/s IP"
                  << " | " << packets_ << " packets total";
        std::cout << " | protocols=";
        const char* separator = "";
        for (unsigned protocol = 0; protocol < interval.protocols.size(); ++protocol) {
            const auto count = interval.protocols[protocol];
            if (count) {
                std::cout << separator << protocol_name(protocol) << '(' << protocol << ")=" << count;
                separator = ", ";
            }
        }
        if (interval.decoded == 0) {
            std::cout << "none";
        }
        if (final) {
            std::cout << " | " << rate(bytes_ * 8.0 / 1e6, seconds_) << " Mb/s IP session average";
        }
        std::cout << '\n' << std::flush;
    }

private:
    std::uint64_t packets_ = 0;
    std::uint64_t bytes_ = 0;
    double seconds_ = 0;
};

// List supported capture backends and output flags.
void usage(std::ostream& output) {
    output << "Usage: cpp-sniffer [--threaded] [--stats] [--metrics-only | --packet-lines] INTERFACE\n"
           << "       cpp-sniffer [--threaded] [--stats] [--metrics-only | --packet-lines] --raw INTERFACE\n"
           << "       cpp-sniffer [--threaded] [--stats] [--metrics-only | --packet-lines] --hex-stdin\n"
           << "       cpp-sniffer [--threaded] [--stats] [--metrics-only | --packet-lines] --pcap FILE\n"
           << "       cpp-sniffer --config FILE\n";
}

}  // namespace

// Select the capture backend and output mode, then report the session result.
int main(int argc, char* argv[]) {
    CaptureConfig config;
    while (argc > 1) {
        const std::string flag = argv[1];
        if (flag == "--threaded" && !config.threaded) {
            config.threaded = true;
        } else if (flag == "--metrics-only" && !config.metrics_only) {
            config.metrics_only = true;
        } else if (flag == "--packet-lines" && !config.packet_lines) {
            config.packet_lines = true;
        } else if (flag == "--stats" && !config.stats) {
            config.stats = true;
        } else {
            break;
        }
        --argc;
        ++argv;
    }
    const std::string option = argc > 1 ? argv[1] : "";
    if (argc == 2 && option == "--help") {
        usage(std::cout);
        return 0;
    }

    try {
        if (argc == 3 && option == "--config" && !config.threaded && !config.stats &&
            !config.metrics_only && !config.packet_lines) {
            config = load_config(argv[2]);
        } else if (argc == 2 && option == "--hex-stdin") {
            config.backend = CaptureBackend::hex_stdin;
        } else if (argc == 3 && option == "--pcap") {
            config.backend = CaptureBackend::pcap;
            config.pcap_file = argv[2];
        } else if (argc == 3 && option == "--raw") {
            config.backend = CaptureBackend::raw;
            config.interface = argv[2];
        } else if (argc == 2 && !option.empty() && option[0] != '-') {
            config.interface = argv[1];
        } else {
            usage(std::cerr);
            return 2;
        }

        if (config.metrics_only && config.packet_lines) {
            throw std::runtime_error("choose either metrics-only or packet-lines output");
        }

        std::unique_ptr<PacketSource> source;
        LinuxPacketSource* live_source = nullptr;
        if (config.backend == CaptureBackend::hex_stdin) {
            source = std::make_unique<HexPacketSource>(std::cin);
        } else if (config.backend == CaptureBackend::pcap) {
            source = std::make_unique<PcapPacketSource>(config.pcap_file);
        } else {
            const auto mode = config.backend == CaptureBackend::raw
                ? LinuxPacketSource::Mode::raw_ethernet : LinuxPacketSource::Mode::cooked;
            auto socket = std::make_unique<LinuxPacketSource>(config.interface.c_str(), mode);
            live_source = socket.get();
            if (config.stats || !config.packet_lines) {
                if (std::signal(SIGINT, interrupt_capture) == SIG_ERR) {
                    throw std::runtime_error("cannot install capture interrupt handler");
                }
                socket->stop_on(interrupted);
            }
            source = std::move(socket);
        }

        if (config.packet_lines) {
            std::cout << std::unitbuf;
        }
        IpPacketDecoder decoder;
        StreamPacketSink sink(std::cout);
        const unsigned cpus = config.cpus ? config.cpus : (config.threaded ? 2 : 1);
        const std::size_t queue_capacity = config.queue_capacity
            ? config.queue_capacity : default_worker_queue_capacity;
        const auto start = std::chrono::steady_clock::now();
        CaptureMetrics metrics;
        if (config.metrics_only) {
            metrics = run_metrics(*source, decoder, cpus - 1, report_interval, queue_capacity);
        } else if (!config.packet_lines) {
            metrics = run_metrics(*source, decoder, cpus - 1, ConsoleReport{}, queue_capacity);
        } else {
            metrics = cpus > 1 ? run_threaded(*source, decoder, sink, cpus - 1, queue_capacity)
                               : run(*source, decoder, sink);
        }
        if (config.stats) {
            const std::chrono::duration<double> elapsed = std::chrono::steady_clock::now() - start;
            const double seconds = elapsed.count();
            const double bytes_per_second = seconds > 0 ? metrics.decoded_ip_bytes / seconds : 0;
            std::cerr << "packets_read=" << metrics.packets_read
                      << " decoded=" << metrics.decoded << " skipped=" << metrics.skipped
                      << " unprocessed=" << metrics.packets_read - metrics.decoded - metrics.skipped
                      << " decoded_ip_bytes=" << metrics.decoded_ip_bytes
                      << " elapsed_seconds=" << seconds
                      << " packets_per_second=" << (seconds > 0 ? metrics.decoded / seconds : 0)
                      << " ip_bytes_per_second=" << bytes_per_second
                      << " ip_bits_per_second=" << 8 * bytes_per_second
                      << " queue_high_water=" << metrics.queue_high_water
                      << " queue_waits=" << metrics.queue_waits;
            if (live_source) {
                std::cerr << " kernel_drops=" << live_source->kernel_drops();
            }
            std::cerr << '\n';
        }
        return std::cout ? 0 : 1;
    } catch (const std::runtime_error& error) {
        std::cerr << "cpp-sniffer: " << error.what() << '\n';
        return 1;
    }
}

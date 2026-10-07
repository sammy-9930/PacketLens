#include "sniffer/sniffer.h"

#include "pipeline/worker_queues.h"
#include "pipeline/packet_output.h"
#include "pipeline/timed_metrics.h"

#include <sched.h>

#include <exception>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

namespace {

using capture_pipeline::WorkerQueues;
using capture_pipeline::PacketOutput;
using capture_pipeline::TimedMetrics;

class DecodeThreads {
public:
    // Reserve thread storage and allocate one exception slot per worker.
    DecodeThreads(WorkerQueues& queue, unsigned count)
        : queue_(queue), errors_(count) {
        threads_.reserve(count);
    }

    // Close input and join any workers that were started.
    ~DecodeThreads() { join(); }

    // Launch a decoder and cancel the pipeline if its task throws.
    template <typename Task, typename Cancel>
    void start(unsigned index, const Task& task, const Cancel& cancel) {
        threads_.emplace_back([this, index, task, cancel] {
            try {
                task(index);
            } catch (...) {
                errors_[index] = std::current_exception();
                cancel();
                queue_.close(true);
            }
        });
    }

    // Close input so workers can drain it, then join each active worker.
    void join() {
        queue_.close();
        for (auto& thread : threads_) {
            if (thread.joinable()) {
                thread.join();
            }
        }
    }

    // Propagate the first recorded worker failure after all workers have joined.
    void rethrow_error() const {
        for (const auto& error : errors_) {
            if (error) {
                std::rethrow_exception(error);
            }
        }
    }

private:
    WorkerQueues& queue_;
    std::vector<std::exception_ptr> errors_;
    std::vector<std::thread> threads_;
};

// Select the result-handling strategy once, outside the per-packet decode loop.
template <typename Output>
CaptureMetrics run_workers(PacketSource& source, const PacketDecoder& decoder,
                           unsigned count, WorkerQueues& queue, Output& output) {
    DecodeThreads threads(queue, count);
    const auto decode = [&](unsigned index) {
        auto& input = queue.worker(index);
        auto&& result = output.worker(index);
        const auto publish = [&] { return result.publish(); };
        Packet packet{};
        PacketMetadata metadata{};
        while (input.pop(packet, publish)) {
            const bool decoded = decoder.decode(packet, metadata);
            if (!result.record(decoded, metadata)) {
                return;
            }
        }
        result.publish();
    };

    CaptureMetrics metrics;
    std::exception_ptr capture_error;
    try {
        for (unsigned index = 0; index < count; ++index) {
            threads.start(index, decode, [&] { output.cancel(); });
        }
        Packet packet{};
        while (!queue.closed() && source.next(packet)) {
            ++metrics.packets_read;
            if (!queue.push(std::move(packet))) {
                break;
            }
        }
    } catch (...) {
        capture_error = std::current_exception();
    }

    // Decode workers flush partial batches before the output strategy finishes.
    threads.join();
    output.finish(metrics);
    threads.rethrow_error();
    if (capture_error) {
        std::rethrow_exception(capture_error);
    }
    metrics.queue_high_water = queue.high_water();
    metrics.queue_waits = queue.waits();
    return metrics;
}

}  // namespace

unsigned available_capture_cpus() {
    cpu_set_t mask;
    if (sched_getaffinity(0, sizeof(mask), &mask) == 0) {
        const auto count = CPU_COUNT(&mask);
        if (count > 0) {
            return static_cast<unsigned>(count);
        }
    }
    const auto count = std::thread::hardware_concurrency();
    return count ? count : 1;
}

CaptureMetrics run_threaded(PacketSource& source, const PacketDecoder& decoder, PacketSink& sink,
                            unsigned workers, std::size_t queue_capacity) {
    if (workers == 0) {
        throw std::invalid_argument("threaded capture requires at least one worker");
    }
    if (!sink.ready()) {
        return {};
    }

    WorkerQueues queue(workers, queue_capacity);
    PacketOutput output(sink, queue);
    return run_workers(source, decoder, workers, queue, output);
}

CaptureMetrics run_metrics(PacketSource& source, const PacketDecoder& decoder,
                           unsigned workers, const MetricsReporter& reporter,
                           std::size_t queue_capacity) {
    TimedMetrics output(workers ? workers : 1, reporter);
    if (workers) {
        WorkerQueues queue(workers, queue_capacity);
        return run_workers(source, decoder, workers, queue, output);
    }

    CaptureMetrics metrics;
    Packet packet{};
    PacketMetadata metadata{};
    auto& counters = output.worker(0);
    while (source.next(packet)) {
        ++metrics.packets_read;
        counters.record(decoder.decode(packet, metadata), metadata);
        counters.publish();
    }
    output.finish(metrics);
    return metrics;
}

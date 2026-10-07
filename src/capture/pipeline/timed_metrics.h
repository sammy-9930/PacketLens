#ifndef SNIFFER_PIPELINE_TIMED_METRICS_H
#define SNIFFER_PIPELINE_TIMED_METRICS_H

#include "sniffer/sniffer.h"

#include <chrono>
#include <condition_variable>
#include <exception>
#include <mutex>
#include <thread>
#include <vector>

namespace capture_pipeline {

// Each decoder accumulates locally and publishes batches into its own slot.
class WorkerMetrics {
public:
    // Update the worker-local counters and publish when the batch reaches 64 packets.
    bool record(bool decoded, const PacketMetadata& metadata) {
        if (decoded) {
            ++pending_.decoded;
            pending_.decoded_ip_bytes += metadata.length;
            ++pending_.protocols.at(metadata.protocol);
        } else {
            ++pending_.skipped;
        }
        if (pending_.decoded + pending_.skipped >= 64) {
            publish();
        }
        return true;
    }

    // Transfer local counts into this worker’s shared slot under its mutex.
    bool publish() {
        if (pending_.decoded == 0 && pending_.skipped == 0) {
            return true;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        add(published_, pending_);
        pending_ = {};
        return true;
    }

    // Merge and clear the published slot so later intervals only see new counts.
    void drain(ProtocolMetrics& interval) {
        std::lock_guard<std::mutex> lock(mutex_);
        add(interval, published_);
        published_ = {};
    }

private:
    // Add packet, byte, and protocol counts from one snapshot into another.
    static void add(ProtocolMetrics& target, const ProtocolMetrics& delta) {
        target.decoded += delta.decoded;
        target.skipped += delta.skipped;
        target.decoded_ip_bytes += delta.decoded_ip_bytes;
        for (std::size_t i = 0; i < target.protocols.size(); ++i) {
            target.protocols[i] += delta.protocols[i];
        }
    }

    std::mutex mutex_;
    ProtocolMetrics pending_;  // Owned by the worker.
    ProtocolMetrics published_;  // Shared with the reporter under mutex_.
};

class TimedMetrics {
public:
    // Allocate one slot per decoder and start the periodic reporter.
    TimedMetrics(unsigned slots, const MetricsReporter& reporter)
        : slots_(slots), reporter_(reporter), timer_([this] { report(); }) {}

    // Stop and join the reporter if the caller exits before finish.
    ~TimedMetrics() { join(); }

    // Return the counters owned by the worker at this index.
    WorkerMetrics& worker(unsigned index) { return slots_[index]; }

    // Decoders can still publish their partial counters after input is cancelled.
    void cancel() {}

    // Join after the final interval, then return totals or propagate a reporter failure.
    void finish(CaptureMetrics& metrics) {
        join();
        if (error_) {
            std::rethrow_exception(error_);
        }
        metrics.decoded = total_.decoded;
        metrics.skipped = total_.skipped;
        metrics.decoded_ip_bytes = total_.decoded_ip_bytes;
    }

private:
    // Wake the timer for an immediate final drain and wait for it to exit.
    void join() {
        if (!timer_.joinable()) {
            return;
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            finished_ = true;
        }
        changed_.notify_one();
        timer_.join();
    }

    // Merge published counts each interval and pass elapsed wall time to the callback.
    void report() {
        try {
            auto start = started_;
            std::unique_lock<std::mutex> lock(mutex_);
            for (;;) {
                const bool final = changed_.wait_until(lock, start + std::chrono::seconds(1),
                                                       [this] { return finished_; });
                // Capture shutdown can signal the timer even while a callback is running.
                lock.unlock();
                ProtocolMetrics interval;
                for (auto& slot : slots_) {
                    slot.drain(interval);
                }
                const auto now = std::chrono::steady_clock::now();
                total_.decoded += interval.decoded;
                total_.skipped += interval.skipped;
                total_.decoded_ip_bytes += interval.decoded_ip_bytes;
                reporter_(interval, std::chrono::duration<double>(now - start).count(), final);
                if (final) {
                    break;
                }
                start = now;
                lock.lock();
            }
        } catch (...) {
            error_ = std::current_exception();
        }
    }

    std::vector<WorkerMetrics> slots_;
    const MetricsReporter& reporter_;
    std::mutex mutex_;
    std::condition_variable changed_;
    bool finished_ = false;
    ProtocolMetrics total_;
    std::exception_ptr error_;
    const std::chrono::steady_clock::time_point started_ = std::chrono::steady_clock::now();
    std::thread timer_;
};

}  // namespace capture_pipeline

#endif

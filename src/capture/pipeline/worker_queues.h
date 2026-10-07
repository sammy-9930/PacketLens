#ifndef SNIFFER_PIPELINE_WORKER_QUEUES_H
#define SNIFFER_PIPELINE_WORKER_QUEUES_H

#include "bounded_queue.h"
#include "sniffer/packet_source.h"

#include <atomic>
#include <deque>

namespace capture_pipeline {

class WorkerQueues {
public:
    // The reader produces into every queue. Each decoder consumes from one queue.
    WorkerQueues(unsigned workers, std::size_t capacity) {
        for (unsigned index = 0; index < workers; ++index) {
            queues_.emplace_back(capacity);
        }
    }

    // Advance the round-robin index only after transferring the packet.
    bool push(Packet&& packet) {
        if (closed() || !queues_[next_worker_].push(std::move(packet))) {
            return false;
        }
        next_worker_ = (next_worker_ + 1) % queues_.size();
        return true;
    }

    // Bind a decoder to its own input queue.
    BoundedQueue<Packet>& worker(unsigned index) { return queues_[index]; }

    // Wake all workers and any producer blocked on a full queue.
    void close(bool cancel = false) {
        closed_.store(true, std::memory_order_relaxed);
        for (auto& queue : queues_) {
            queue.close(cancel);
        }
    }

    // Read the stop flag without taking any worker's queue mutex.
    bool closed() const { return closed_.load(std::memory_order_relaxed); }

    // Report the peak of any one worker queue after the pipeline has joined.
    std::size_t high_water() const {
        std::size_t peak = 0;
        for (const auto& queue : queues_) {
            peak = std::max(peak, queue.high_water());
        }
        return peak;
    }

    // Sum the producer's full-queue waits after the pipeline has joined.
    std::uint64_t waits() const {
        std::uint64_t total = 0;
        for (const auto& queue : queues_) {
            total += queue.waits();
        }
        return total;
    }

private:
    std::deque<BoundedQueue<Packet>> queues_;
    std::size_t next_worker_ = 0;
    std::atomic<bool> closed_{false};
};

}  // namespace capture_pipeline

#endif

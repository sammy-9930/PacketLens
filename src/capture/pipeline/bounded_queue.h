#ifndef SNIFFER_PIPELINE_BOUNDED_QUEUE_H
#define SNIFFER_PIPELINE_BOUNDED_QUEUE_H

#include <algorithm>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <stdexcept>
#include <utility>

namespace capture_pipeline {

template <typename Value>
class BoundedQueue {
public:
    explicit BoundedQueue(std::size_t capacity) : capacity_(capacity) {
        if (capacity_ == 0) {
            throw std::invalid_argument("queue capacity must be positive");
        }
    }

    // Wait for space, then transfer ownership to the queue. Return false after close.
    bool push(Value&& value) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!closed_ && items_.size() == capacity_) {
            ++waits_;
        }
        space_available_.wait(lock, [this] { return closed_ || items_.size() < capacity_; });
        if (closed_) {
            return false;
        }
        items_.push_back(std::move(value));
        high_water_ = std::max(high_water_, items_.size());
        item_available_.notify_one();
        return true;
    }

    // Take the oldest item. Call on_idle before blocking and stop if it returns false.
    template <typename OnIdle>
    bool pop(Value& value, const OnIdle& on_idle) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!closed_ && items_.empty()) {
            // A worker may publish to the output queue here. Release the input lock first.
            lock.unlock();
            if (!on_idle()) {
                return false;
            }
            lock.lock();
        }
        item_available_.wait(lock, [this] { return closed_ || !items_.empty(); });
        if (cancelled_ || items_.empty()) {
            return false;
        }
        value = std::move(items_.front());
        items_.pop_front();
        space_available_.notify_one();
        return true;
    }

    // Wake producers and consumers. Normal close drains queued items. Cancellation discards them.
    void close(bool cancel = false) {
        std::lock_guard<std::mutex> lock(mutex_);
        closed_ = true;
        cancelled_ = cancelled_ || cancel;
        item_available_.notify_all();
        space_available_.notify_all();
    }

    // Check whether the queue has stopped accepting input.
    bool closed() {
        std::lock_guard<std::mutex> lock(mutex_);
        return closed_;
    }

    // Read the peak occupancy after all queue users have joined.
    std::size_t high_water() const { return high_water_; }
    // Read the number of pushes that found a full queue after all users have joined.
    std::uint64_t waits() const { return waits_; }

private:
    const std::size_t capacity_;
    std::mutex mutex_;
    std::condition_variable item_available_;
    std::condition_variable space_available_;
    std::deque<Value> items_;
    bool closed_ = false;
    bool cancelled_ = false;
    std::size_t high_water_ = 0;
    std::uint64_t waits_ = 0;
};

}  // namespace capture_pipeline

#endif

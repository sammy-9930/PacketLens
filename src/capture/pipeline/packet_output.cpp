#include "packet_output.h"

#include <utility>

namespace capture_pipeline {

bool BatchedWorkerOutput::record(bool decoded, PacketMetadata& metadata) {
    constexpr std::size_t batch_size = 16;
    if (batch_.empty()) {
        batch_.reserve(batch_size);
    }
    batch_.push_back({decoded, decoded ? std::move(metadata) : PacketMetadata{}});
    return batch_.size() < batch_size || publish();
}

bool BatchedWorkerOutput::publish() {
    if (batch_.empty()) {
        return true;
    }
    const bool accepted = results_.push(std::move(batch_));
    batch_.clear();
    return accepted;
}

PacketOutput::PacketOutput(PacketSink& sink, WorkerQueues& input)
    : sink_(sink), input_(input), writer_([this] { write(); }) {}

PacketOutput::~PacketOutput() {
    join();
}

void PacketOutput::cancel() {
    results_.close(true);
    input_.close(true);
}

void PacketOutput::finish(CaptureMetrics& metrics) {
    join();
    if (error_) {
        std::rethrow_exception(error_);
    }
    metrics.decoded = written_.decoded;
    metrics.skipped = written_.skipped;
    metrics.decoded_ip_bytes = written_.decoded_ip_bytes;
}

void PacketOutput::join() {
    if (writer_.joinable()) {
        results_.close();
        writer_.join();
    }
}

void PacketOutput::write() {
    try {
        ResultBatch batch;
        while (results_.pop(batch, [] { return true; })) {
            for (const auto& result : batch) {
                if (!sink_.ready()) {
                    cancel();
                    return;
                }
                if (result.decoded) {
                    sink_.write(result.metadata);
                    ++written_.decoded;
                    written_.decoded_ip_bytes += result.metadata.length;
                } else {
                    ++written_.skipped;
                }
            }
        }
    } catch (...) {
        error_ = std::current_exception();
        cancel();
    }
}

}  // namespace capture_pipeline

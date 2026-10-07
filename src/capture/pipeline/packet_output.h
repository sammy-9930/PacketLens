#ifndef SNIFFER_PIPELINE_PACKET_OUTPUT_H
#define SNIFFER_PIPELINE_PACKET_OUTPUT_H

#include "worker_queues.h"
#include "sniffer/sniffer.h"

#include <exception>
#include <thread>
#include <vector>

namespace capture_pipeline {

struct DecodeResult {
    bool decoded;
    PacketMetadata metadata;
};

using ResultBatch = std::vector<DecodeResult>;

class BatchedWorkerOutput {
public:
    // Bind a worker-local batch to the writer queue.
    explicit BatchedWorkerOutput(BoundedQueue<ResultBatch>& results) : results_(results) {}

    // Append one result and publish a full batch. A decoded result takes ownership of metadata.
    bool record(bool decoded, PacketMetadata& metadata);
    // Hand off a partial batch. Return false if the writer queue has closed.
    bool publish();

private:
    BoundedQueue<ResultBatch>& results_;
    ResultBatch batch_;
};

class PacketOutput {
public:
    // Start the writer. The sink and input queues must outlive this object.
    PacketOutput(PacketSink& sink, WorkerQueues& input);
    // Close the result queue and join the writer during scope exit.
    ~PacketOutput();

    // Create an independent result batch for a decode worker.
    BatchedWorkerOutput worker(unsigned) { return BatchedWorkerOutput(results_); }
    // Cancel the input and result queues so blocked workers and the reader can stop.
    void cancel();
    // Drain the writer, propagate output failures, and copy the written totals.
    void finish(CaptureMetrics& metrics);

private:
    // Consume batches on the writer thread, the sole sink user after startup.
    void write();
    // Allow queued batches to drain, then join the writer once.
    void join();

    PacketSink& sink_;
    WorkerQueues& input_;
    BoundedQueue<ResultBatch> results_{64};
    CaptureMetrics written_;
    std::exception_ptr error_;
    std::thread writer_;
};

}  // namespace capture_pipeline

#endif

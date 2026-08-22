#ifndef SNIFFER_PACKET_SINK_H
#define SNIFFER_PACKET_SINK_H

#include <iosfwd>

struct PacketMetadata;

// Map an IP protocol number to its display name, or Unknown if it is unmapped.
const char* protocol_name(unsigned protocol);

class PacketSink {
public:
    // Allow sinks to be destroyed through the base interface.
    virtual ~PacketSink() = default;
    // The capture loop checks readiness before requesting another packet.
    virtual bool ready() const = 0;
    // Accept metadata for one successfully decoded packet.
    virtual void write(const PacketMetadata& metadata) = 0;
};

class StreamPacketSink final : public PacketSink {
public:
    // Borrow the output stream for the lifetime of this sink.
    explicit StreamPacketSink(std::ostream& output) : output_(output) {}

    // Check whether the stream can still accept output.
    bool ready() const override;
    // Write one human-readable packet summary followed by a newline.
    void write(const PacketMetadata& metadata) override;

private:
    std::ostream& output_;
};

#endif

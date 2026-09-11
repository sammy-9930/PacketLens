#include "sniffer/sniffer.h"

CaptureMetrics run(PacketSource& source, const PacketDecoder& decoder, PacketSink& sink) {
    // Reuse the packet buffer and metadata across capture iterations.
    CaptureMetrics metrics;
    Packet packet{};
    PacketMetadata metadata{};
    while (sink.ready() && source.next(packet)) {
        ++metrics.packets_read;
        if (decoder.decode(packet, metadata)) {
            ++metrics.decoded;
            metrics.decoded_ip_bytes += metadata.length;
            sink.write(metadata);
        } else {
            ++metrics.skipped;
        }
    }
    return metrics;
}

void run(PacketSource& source, std::ostream& output) {
    IpPacketDecoder decoder;
    StreamPacketSink sink(output);
    run(source, decoder, sink);
}

#ifndef SNIFFER_TEST_PACKET_PIPELINE_H
#define SNIFFER_TEST_PACKET_PIPELINE_H

#include "sniffer/decoder.h"
#include "sniffer/packet_sink.h"

#include <gmock/gmock.h>

// Capture-loop tests can replace all three stages without opening a socket.
class MockPacketSource : public PacketSource {
public:
    MOCK_METHOD(bool, next, (Packet&), (override));
};

class MockPacketDecoder : public PacketDecoder {
public:
    MOCK_METHOD(bool, decode, (const Packet&, PacketMetadata&), (const, override));
};

class MockPacketSink : public PacketSink {
public:
    MOCK_METHOD(bool, ready, (), (const, override));
    MOCK_METHOD(void, write, (const PacketMetadata&), (override));
};

#endif

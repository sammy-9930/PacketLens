#include "sniffer/sniffer.h"
#include "mocks/packet_pipeline.h"
#include "sniffer/capture/hex_replay/hex_packet_source.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <array>
#include <chrono>
#include <future>
#include <sstream>
#include <stdexcept>
#include <thread>

namespace {

using testing::_;
using testing::DoAll;
using testing::Field;
using testing::HasSubstr;
using testing::InSequence;
using testing::Return;
using testing::SetArgReferee;
using testing::StrictMock;

// Build a minimal IPv4 fixture with the requested protocol number.
Packet ipv4(std::uint8_t protocol) {
    return {0x0800, {0x45, 0, 0, 20, 0, 0, 0, 0, 64, protocol,
                     0, 0, 192, 0, 2, 1, 198, 51, 100, 2}};
}

// Build a minimal IPv6 fixture with the requested next-header number.
Packet ipv6(std::uint8_t next) {
    Packet packet{0x86dd, std::vector<std::uint8_t>(40)};
    packet.bytes[0] = 0x60;
    packet.bytes[6] = next;
    packet.bytes[23] = 1;
    packet.bytes[39] = 2;
    return packet;
}

TEST(ProtocolDecoder, NamesCommonIPv4ProtocolsAndIncludesEndpoints) {
    std::ostringstream output;
    EXPECT_TRUE(print_packet(ipv4(6), output));
    EXPECT_TRUE(print_packet(ipv4(17), output));
    EXPECT_TRUE(print_packet(ipv4(1), output));
    EXPECT_EQ("IPv4 192.0.2.1 -> 198.51.100.2 protocol=TCP(6) bytes=20\n"
              "IPv4 192.0.2.1 -> 198.51.100.2 protocol=UDP(17) bytes=20\n"
              "IPv4 192.0.2.1 -> 198.51.100.2 protocol=ICMP(1) bytes=20\n",
              output.str());
}

TEST(ProtocolDecoder, ReportsAnUnmappedProtocolNumber) {
    std::ostringstream output;
    EXPECT_TRUE(print_packet(ipv4(253), output));
    EXPECT_THAT(output.str(), HasSubstr("protocol=Unknown(253)"));
}

TEST(ProtocolDecoder, FollowsIPv6ExtensionHeaders) {
    Packet packet = ipv6(0);
    packet.bytes.resize(56);
    packet.bytes[5] = 16;
    // Chain Hop-by-Hop Options to Destination Options, then ICMPv6.
    packet.bytes[40] = 60;
    packet.bytes[48] = 58;
    std::ostringstream output;
    ASSERT_TRUE(print_packet(packet, output));
    EXPECT_EQ("IPv6 ::1 -> ::2 protocol=ICMPv6(58) bytes=56\n", output.str());
}

TEST(ProtocolDecoder, RejectsMalformedPacketsAndIgnoresNonIpFrames) {
    Packet short_ipv4 = ipv4(6);
    short_ipv4.bytes.pop_back();
    Packet invalid_ihl = ipv4(6);
    invalid_ihl.bytes[0] = 0x46;
    Packet invalid_extension = ipv6(60);
    invalid_extension.bytes.resize(48);
    invalid_extension.bytes[5] = 8;
    invalid_extension.bytes[41] = 1;

    std::ostringstream output;
    EXPECT_FALSE(print_packet(short_ipv4, output));
    EXPECT_FALSE(print_packet(invalid_ihl, output));
    EXPECT_FALSE(print_packet(invalid_extension, output));
    EXPECT_FALSE(print_packet(Packet{0x0806, {}}, output));
    EXPECT_TRUE(output.str().empty());
}

TEST(CaptureLoop, SkipsNonIpPacketsAndStopsWhenSourceEnds) {
    StrictMock<MockPacketSource> source;
    const InSequence sequence;
    EXPECT_CALL(source, next(_)).WillOnce([](Packet& packet) {
        packet = Packet{0x0806, {}};
        return true;
    });
    EXPECT_CALL(source, next(_)).WillOnce([](Packet& packet) {
        packet = ipv4(17);
        return true;
    });
    EXPECT_CALL(source, next(_)).WillOnce(Return(false));

    std::ostringstream output;
    run(source, output);
    EXPECT_EQ("IPv4 192.0.2.1 -> 198.51.100.2 protocol=UDP(17) bytes=20\n",
              output.str());
}

TEST(CaptureLoop, WritesOnlyMetadataFromAcceptedPackets) {
    StrictMock<MockPacketSource> source;
    StrictMock<MockPacketDecoder> decoder;
    StrictMock<MockPacketSink> sink;
    const InSequence sequence;
    const PacketMetadata metadata{IpVersion::v4, "192.0.2.1", "198.51.100.2", 17, 20};

    EXPECT_CALL(sink, ready()).WillOnce(Return(true));
    EXPECT_CALL(source, next(_))
        .WillOnce(DoAll(SetArgReferee<0>(Packet{0x0806, {}}), Return(true)));
    // StrictMock rejects any sink write for this packet.
    EXPECT_CALL(decoder, decode(Field(&Packet::ether_type, 0x0806), _))
        .WillOnce(Return(false));

    EXPECT_CALL(sink, ready()).WillOnce(Return(true));
    EXPECT_CALL(source, next(_))
        .WillOnce(DoAll(SetArgReferee<0>(ipv4(17)), Return(true)));
    EXPECT_CALL(decoder, decode(Field(&Packet::ether_type, 0x0800), _))
        .WillOnce(DoAll(SetArgReferee<1>(metadata), Return(true)));
    EXPECT_CALL(sink, write(_)).WillOnce([&](const PacketMetadata& written) {
        EXPECT_EQ(metadata.version, written.version);
        EXPECT_EQ(metadata.source, written.source);
        EXPECT_EQ(metadata.destination, written.destination);
        EXPECT_EQ(metadata.protocol, written.protocol);
        EXPECT_EQ(metadata.length, written.length);
    });

    EXPECT_CALL(sink, ready()).WillOnce(Return(true));
    EXPECT_CALL(source, next(_)).WillOnce(Return(false));

    run(source, decoder, sink);
}

TEST(CaptureLoop, StopsReadingWhenSinkBecomesUnavailable) {
    StrictMock<MockPacketSource> source;
    StrictMock<MockPacketDecoder> decoder;
    StrictMock<MockPacketSink> sink;
    const InSequence sequence;

    EXPECT_CALL(sink, ready()).WillOnce(Return(true));
    EXPECT_CALL(source, next(_))
        .WillOnce(DoAll(SetArgReferee<0>(ipv4(17)), Return(true)));
    EXPECT_CALL(decoder, decode(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(PacketMetadata{}), Return(true)));
    EXPECT_CALL(sink, write(_));
    // An extra source read after the sink becomes unavailable fails this test.
    EXPECT_CALL(sink, ready()).WillOnce(Return(false));

    run(source, decoder, sink);
}

TEST(ThreadedCapture, DrainsMoreThanOneQueueWithoutLosingResults) {
    std::string input;
    std::vector<std::string> expected;
    for (int i = 0; i < 80; ++i) {
        input += "450000140000000040060000c0000201c6336402\n";
        input += "450000140000000040110000c0000201c6336402\n";
        expected.emplace_back("IPv4 192.0.2.1 -> 198.51.100.2 protocol=TCP(6) bytes=20");
        expected.emplace_back("IPv4 192.0.2.1 -> 198.51.100.2 protocol=UDP(17) bytes=20");
    }
    std::istringstream records(input);
    HexPacketSource source(records);
    IpPacketDecoder decoder;
    std::ostringstream output;
    StreamPacketSink sink(output);

    const auto metrics = run_threaded(source, decoder, sink, 4);

    std::istringstream lines(output.str());
    std::vector<std::string> actual;
    for (std::string line; std::getline(lines, line);) {
        actual.push_back(line);
    }
    EXPECT_THAT(actual, testing::UnorderedElementsAreArray(expected));
    EXPECT_EQ(160u, metrics.packets_read);
    EXPECT_EQ(160u, metrics.decoded);
    EXPECT_EQ(3200u, metrics.decoded_ip_bytes);
    EXPECT_EQ(0u, metrics.skipped);
    EXPECT_GT(metrics.queue_high_water, 0u);
    EXPECT_LE(metrics.queue_high_water, 64u);
}

TEST(ThreadedCapture, DispatchesRoundRobinToDedicatedWorkers) {
    std::istringstream records("450000140000000040010000c0000201c6336402\n"
                               "450000140000000040020000c0000201c6336402\n"
                               "450000140000000040030000c0000201c6336402\n"
                               "450000140000000040040000c0000201c6336402\n");
    HexPacketSource source(records);
    StrictMock<MockPacketDecoder> decoder;
    const IpPacketDecoder ip_decoder;
    std::array<std::thread::id, 4> threads{};
    EXPECT_CALL(decoder, decode(_, _)).Times(4)
        .WillRepeatedly([&](const Packet& packet, PacketMetadata& metadata) {
            threads.at(packet.bytes.at(9) - 1) = std::this_thread::get_id();
            return ip_decoder.decode(packet, metadata);
        });

    EXPECT_EQ(4u, run_metrics(source, decoder, 2, [](const ProtocolMetrics&, double, bool) {}).decoded);
    EXPECT_EQ(threads[0], threads[2]);
    EXPECT_EQ(threads[1], threads[3]);
    EXPECT_NE(threads[0], threads[1]);
}

TEST(ThreadedCapture, WritesCompletedPacketWhileEarlierPacketIsStillDecoding) {
    std::istringstream records("450000140000000040060000c0000201c6336402\n"
                               "450000140000000040110000c0000201c6336402");
    HexPacketSource source(records);
    StrictMock<MockPacketDecoder> decoder;
    StrictMock<MockPacketSink> sink;
    std::promise<void> second_written;
    auto done = second_written.get_future();
    const IpPacketDecoder ip_decoder;

    EXPECT_CALL(sink, ready()).WillRepeatedly(Return(true));
    EXPECT_CALL(sink, write(Field(&PacketMetadata::protocol, 17u)))
        .WillOnce([&](const PacketMetadata&) { second_written.set_value(); });
    EXPECT_CALL(sink, write(Field(&PacketMetadata::protocol, 6u)));
    EXPECT_CALL(decoder, decode(_, _)).Times(2)
        .WillRepeatedly([&](const Packet& packet, PacketMetadata& metadata) {
            if (packet.bytes[9] == 6 &&
                done.wait_for(std::chrono::seconds(2)) != std::future_status::ready) {
                throw std::runtime_error("completed packet could not reach the sink");
            }
            return ip_decoder.decode(packet, metadata);
        });

    EXPECT_EQ(2u, run_threaded(source, decoder, sink, 2).decoded);
}

TEST(ThreadedCapture, PropagatesWorkerFailure) {
    std::istringstream records("450000140000000040060000c0000201c6336402");
    HexPacketSource source(records);
    StrictMock<MockPacketDecoder> decoder;
    std::ostringstream output;
    StreamPacketSink sink(output);
    EXPECT_CALL(decoder, decode(_, _)).WillOnce([](const Packet&, PacketMetadata&) -> bool {
        throw std::runtime_error("decoder error");
    });

    EXPECT_THROW(run_threaded(source, decoder, sink, 4), std::runtime_error);
}

TEST(ThreadedCapture, PropagatesWriterFailureAndReleasesWorkers) {
    std::string input;
    for (int i = 0; i < 2048; ++i) {
        input += "450000140000000040110000c0000201c6336402\n";
    }
    std::istringstream records(input);
    HexPacketSource source(records);
    IpPacketDecoder decoder;
    StrictMock<MockPacketSink> sink;
    EXPECT_CALL(sink, ready()).WillRepeatedly(Return(true));
    EXPECT_CALL(sink, write(_)).WillOnce([](const PacketMetadata&) {
        throw std::runtime_error("writer failure");
    });

    EXPECT_THROW(run_threaded(source, decoder, sink, 4), std::runtime_error);
}

TEST(CaptureMetrics, MergesPartialBatchesAndProtocolCountsOnExit) {
    for (const unsigned workers : {0u, 3u}) {
        std::istringstream records("450000140000000040060000c0000201c6336402\n"
                                   "450000140000000040110000c0000201c6336402\n"
                                   "4500\n");
        HexPacketSource source(records);
        IpPacketDecoder decoder;
        ProtocolMetrics totals;
        unsigned finals = 0;
        const auto metrics = run_metrics(source, decoder, workers,
            [&](const ProtocolMetrics& interval, double seconds, bool final) {
                EXPECT_GT(seconds, 0);
                finals += final;
                totals.protocols[6] += interval.protocols[6];
                totals.protocols[17] += interval.protocols[17];
                totals.decoded_ip_bytes += interval.decoded_ip_bytes;
            });

        EXPECT_EQ(1u, finals);
        EXPECT_EQ(3u, metrics.packets_read);
        EXPECT_EQ(2u, metrics.decoded);
        EXPECT_EQ(1u, metrics.skipped);
        EXPECT_EQ(40u, metrics.decoded_ip_bytes);
        EXPECT_EQ(40u, totals.decoded_ip_bytes);
        EXPECT_EQ(1u, totals.protocols[6]);
        EXPECT_EQ(1u, totals.protocols[17]);
    }
}

}  // namespace

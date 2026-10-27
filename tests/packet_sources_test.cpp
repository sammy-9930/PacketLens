#include "sniffer/capture/common/ethernet_frame.h"
#include "sniffer/capture/hex_replay/hex_packet_source.h"

#include <gtest/gtest.h>
#include <sstream>
#include <stdexcept>

TEST(HexPacketSource, ReadsMixedCaseAndFinalRecordWithoutNewline) {
    std::istringstream input("\n4aBc\r\n60");
    HexPacketSource source(input);
    Packet packet{};

    ASSERT_TRUE(source.next(packet));
    EXPECT_EQ(0x0800, packet.ether_type);
    EXPECT_EQ((std::vector<std::uint8_t>{0x4a, 0xbc}), packet.bytes);
    ASSERT_TRUE(source.next(packet));
    EXPECT_EQ(0x86dd, packet.ether_type);
    EXPECT_FALSE(source.next(packet));
}

TEST(HexPacketSource, RejectsInvalidAndOversizedRecords) {
    for (const auto& record : {std::string("4x"), std::string(2 * 65575 + 2, '4')}) {
        std::istringstream input(record);
        HexPacketSource source(input);
        Packet packet{};
        EXPECT_THROW(source.next(packet), std::runtime_error);
    }
}

TEST(EthernetFrame, StripsStackedVlanTagsAndRejectsTruncatedHeaders) {
    const std::uint8_t frame[] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0x88, 0xa8, 0, 1, 0x81, 0, 0, 2, 0x86, 0xdd, 0x60
    };
    Packet packet{};

    EXPECT_FALSE(decode_ethernet_frame(frame, 13, packet));
    EXPECT_FALSE(decode_ethernet_frame(frame, 20, packet));
    ASSERT_TRUE(decode_ethernet_frame(frame, sizeof(frame), packet));
    EXPECT_EQ(0x86dd, packet.ether_type);
    EXPECT_EQ((std::vector<std::uint8_t>{0x60}), packet.bytes);
}

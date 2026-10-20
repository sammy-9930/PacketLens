CXX ?= g++
CXXFLAGS ?= -O2 -Wall -Wextra -Wpedantic
TEST_STD ?= c++14
BENCHMARK_LIBS ?= -lbenchmark
GTEST_LIBS ?= -lgmock_main -lgmock -lgtest

CORE_OBJECTS := build/src/capture/capture_loop.o \
                build/src/capture/threaded_capture.o \
                build/src/capture/pipeline/packet_output.o \
                build/src/capture/common/ethernet_frame.o \
                build/src/decode/ip_decoder.o \
                build/src/output/packet_formatter.o
LINUX_SOCKET_OBJECTS := build/src/capture/linux_socket/linux_packet_source.o
HEX_REPLAY_OBJECTS := build/src/capture/hex_replay/hex_packet_source.o
PCAP_REPLAY_OBJECTS := build/src/capture/pcap_replay/pcap_packet_source.o
CLI_OBJECTS := build/src/main.o build/src/config/config.o $(LINUX_SOCKET_OBJECTS) $(HEX_REPLAY_OBJECTS) $(PCAP_REPLAY_OBJECTS)
TEST_OBJECTS := build/tests/sniffer_test.o build/tests/packet_sources_test.o

BENCHMARK_OBJECTS := build/benchmarks/capture_benchmark.o

.PHONY: all test benchmark clean
all: cpp-sniffer

cpp-sniffer: $(CLI_OBJECTS) $(CORE_OBJECTS)
	$(CXX) $(LDFLAGS) -pthread $^ $(LDLIBS) -o $@

sniffer-test: $(TEST_OBJECTS) $(CORE_OBJECTS) $(HEX_REPLAY_OBJECTS) $(PCAP_REPLAY_OBJECTS)
	$(CXX) $(LDFLAGS) -pthread $^ $(GTEST_LIBS) $(LDLIBS) -o $@

build/src/%.o: src/%.cpp
	mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) -Iinclude $(CXXFLAGS) -std=c++14 -pthread -MMD -MP -c $< -o $@

build/tests/%.o: tests/%.cpp
	mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) -Iinclude $(CXXFLAGS) -std=$(TEST_STD) -pthread -MMD -MP -c $< -o $@

build/benchmarks/%.o: benchmarks/%.cpp
	mkdir -p $(@D)
	$(CXX) $(CPPFLAGS) -Iinclude $(CXXFLAGS) -std=c++14 -pthread -MMD -MP -c $< -o $@

sniffer-benchmark: $(BENCHMARK_OBJECTS) $(CORE_OBJECTS)
	$(CXX) $(LDFLAGS) -pthread $^ $(BENCHMARK_LIBS) $(LDLIBS) -o $@

benchmark: sniffer-benchmark
	./sniffer-benchmark

test: sniffer-test
	./sniffer-test

clean:
	$(RM) -r build
	$(RM) cpp-sniffer sniffer-test sniffer-benchmark main.o sniffer.o sniffer_test.o

-include $(CORE_OBJECTS:.o=.d) $(CLI_OBJECTS:.o=.d) $(TEST_OBJECTS:.o=.d) $(BENCHMARK_OBJECTS:.o=.d)

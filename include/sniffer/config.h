#ifndef SNIFFER_CONFIG_H
#define SNIFFER_CONFIG_H

#include <string>

enum class CaptureBackend { cooked, raw, hex_stdin, pcap };

struct CaptureConfig {
    CaptureBackend backend = CaptureBackend::cooked;
    std::string interface;
    std::string pcap_file;
    bool stats = false;
    bool metrics_only = false;
    bool packet_lines = false;
    unsigned queue_capacity = 0;  // Zero means use the capture default.
    unsigned cpus = 0;  // Zero means use the legacy threaded setting.
    bool threaded = false;
};

// Read and validate a key-value config file, including backend-specific settings.
CaptureConfig load_config(const std::string& path);

#endif

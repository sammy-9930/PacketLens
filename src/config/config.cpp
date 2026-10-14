#include "sniffer/config.h"
#include "sniffer/sniffer.h"

#include <fstream>
#include <limits>
#include <set>
#include <stdexcept>

namespace {

// Strip spaces, tabs, and carriage returns around configuration tokens.
std::string trim(const std::string& text) {
    const auto first = text.find_first_not_of(" \t\r");
    if (first == std::string::npos) {
        return {};
    }
    return text.substr(first, text.find_last_not_of(" \t\r") - first + 1);
}

}  // namespace

CaptureConfig load_config(const std::string& path) {
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error("cannot open config file " + path);
    }

    CaptureConfig config;
    std::set<std::string> keys;
    std::size_t line_number = 0;
    for (std::string line; std::getline(input, line);) {
        ++line_number;
        line = trim(line);
        if (line.empty() || line.front() == '#') {
            continue;
        }

        const auto error = [&](const std::string& message) {
            return std::runtime_error(path + ":" + std::to_string(line_number) + ": " + message);
        };
        const auto equals = line.find('=');
        if (equals == std::string::npos) {
            throw error("expected key=value");
        }
        const auto key = trim(line.substr(0, equals));
        const auto value = trim(line.substr(equals + 1));
        if (!keys.insert(key).second) {
            throw error("duplicate setting '" + key + "'");
        }

        if (key == "backend") {
            if (value == "cooked") {
                config.backend = CaptureBackend::cooked;
            } else if (value == "raw") {
                config.backend = CaptureBackend::raw;
            } else if (value == "hex-stdin") {
                config.backend = CaptureBackend::hex_stdin;
            } else if (value == "pcap") {
                config.backend = CaptureBackend::pcap;
            } else {
                throw error("backend must be cooked, raw, hex-stdin, or pcap");
            }
        } else if (key == "interface") {
            if (value.empty() || value.find_first_of(" \t\r") != std::string::npos ||
                value.find('\0') != std::string::npos) {
                throw error("expected an interface name");
            }
            config.interface = value;
        } else if (key == "pcap_file") {
            if (value.empty() || value.find('\0') != std::string::npos) {
                throw error("expected a PCAP file path");
            }
            config.pcap_file = value;
        } else if (key == "cpus" || key == "queue_capacity") {
            if (key == "cpus" && value == "auto") {
                config.cpus = available_capture_cpus();
                continue;
            }
            const auto invalid = [&] {
                return error(key + " must be a positive integer" +
                             (key == "cpus" ? " or auto" : ""));
            };
            unsigned count = 0;
            for (const char digit : value) {
                if (digit < '0' || digit > '9' ||
                    count > (std::numeric_limits<unsigned>::max() - (digit - '0')) / 10) {
                    throw invalid();
                }
                count = count * 10 + (digit - '0');
            }
            if (count == 0) {
                throw invalid();
            }
            (key == "cpus" ? config.cpus : config.queue_capacity) = count;
        } else if (key == "threaded" || key == "stats" || key == "metrics_only" ||
                   key == "packet_lines") {
            if (value != "true" && value != "false") {
                throw error(key + " must be true or false");
            }
            const bool enabled = value == "true";
            if (key == "threaded") {
                config.threaded = enabled;
            } else if (key == "stats") {
                config.stats = enabled;
            } else if (key == "metrics_only") {
                config.metrics_only = enabled;
            } else {
                config.packet_lines = enabled;
            }
        } else {
            throw error("unknown setting '" + key + "'");
        }
    }
    if (input.bad() || !input.eof()) {
        throw std::runtime_error("cannot read config file " + path);
    }

    if (config.backend == CaptureBackend::pcap && config.pcap_file.empty()) {
        throw std::runtime_error(path + ": pcap_file is required for PCAP replay");
    }
    if (config.backend != CaptureBackend::pcap && !config.pcap_file.empty()) {
        throw std::runtime_error(path + ": pcap_file requires the pcap backend");
    }
    if (config.backend == CaptureBackend::hex_stdin || config.backend == CaptureBackend::pcap) {
        if (!config.interface.empty()) {
            throw std::runtime_error(path + ": replay does not use an interface");
        }
    } else if (config.interface.empty()) {
        throw std::runtime_error(path + ": an interface is required for socket capture");
    }
    return config;
}

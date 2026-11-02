#!/usr/bin/env python3
"""Generate synthetic Ethernet PCAP input and benchmark both replay modes."""

import argparse
from pathlib import Path
import resource
import statistics
import struct
import subprocess
import tempfile
import time


def write_capture(path, count):
    # Alternate IPv4 and IPv6 headers using documentation or loopback addresses.
    packets = [
        bytes.fromhex("0800 450000140000000040110000c0000201c6336402"),
        bytes.fromhex("86dd 6000000000003b40") + bytes(15) + b"\x01"
        + bytes(15) + b"\x02",
    ]
    records = []
    for packet in packets:
        frame = bytes(12) + packet
        records.append(struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame)

    with path.open("wb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        pairs, remainder = divmod(count, 2)
        chunk = b"".join(records) * 1024
        for _ in range(pairs // 1024):
            output.write(chunk)
        output.write(b"".join(records) * (pairs % 1024))
        if remainder:
            output.write(records[0])


def measure(command, count):
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    start = time.perf_counter()
    result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                            text=True, check=True)
    wall = time.perf_counter() - start
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu = (after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime)
    counters = dict(field.split("=") for field in result.stderr.split())
    if (int(counters["packets_read"]), int(counters["decoded"]),
            int(counters["skipped"])) != (count, count, 0):
        raise RuntimeError("unexpected replay counters: " + result.stderr)
    return count / wall, 100 * cpu / wall, int(counters["queue_high_water"]), int(counters["queue_waits"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packets", type=int, default=20_000)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--write-pcap", type=Path, help="generate a reusable capture and exit")
    args = parser.parse_args()
    if args.packets < 1 or args.runs < 1:
        parser.error("packet and run counts must be positive")
    if args.write_pcap:
        write_capture(args.write_pcap, args.packets)
        return

    binary = Path(__file__).resolve().parents[1] / "cpp-sniffer"
    with tempfile.TemporaryDirectory() as directory:
        capture = Path(directory) / "replay.pcap"
        write_capture(capture, args.packets)
        samples = {"single": [], "threaded": []}
        for _ in range(args.runs):
            for mode, results in samples.items():
                flags = ["--threaded"] if mode == "threaded" else []
                results.append(measure([str(binary), *flags, "--packet-lines", "--stats", "--pcap",
                                        str(capture)], args.packets))

    print(f"{args.packets:,} packets, medians across {args.runs} runs")
    print("| Mode | Packets/s | CPU usage | Queue peak | Queue waits |")
    print("| --- | ---: | ---: | ---: | ---: |")
    for mode, results in samples.items():
        rate, cpu, peak, waits = map(statistics.median, zip(*results))
        print(f"| {mode} | {rate:,.0f} | {cpu:.1f}% | {peak:g} | {waits:g} |")


if __name__ == "__main__":
    main()

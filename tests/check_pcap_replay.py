#!/usr/bin/env python3
"""Verify both output paths against the same generated Ethernet PCAP."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PcapReplayTest(unittest.TestCase):
    def test_replays_ipv4_and_ipv6(self):
        with tempfile.TemporaryDirectory() as folder:
            capture = Path(folder) / "sample.pcap"
            subprocess.run(
                [sys.executable, str(ROOT / "benchmarks/replay.py"),
                 "--packets", "4", "--write-pcap", str(capture)], check=True
            )
            command = [str(ROOT / "cpp-sniffer"), "--pcap", str(capture)]
            summary = subprocess.run(command, check=True, capture_output=True, text=True)
            self.assertIn("4 packets total", summary.stdout)
            self.assertIn("protocols=UDP(17)=2, No Next Header(59)=2", summary.stdout)
            self.assertIn("Mb/s IP session average", summary.stdout)
            replay = subprocess.run(
                [command[0], "--packet-lines", *command[1:]],
                check=True, capture_output=True, text=True,
            )
            self.assertEqual(replay.stdout.splitlines(), [
                "IPv4 192.0.2.1 -> 198.51.100.2 protocol=UDP(17) bytes=20",
                "IPv6 ::1 -> ::2 protocol=No Next Header(59) bytes=40",
            ] * 2)

            replay = subprocess.run(
                [command[0], "--threaded", "--metrics-only", *command[1:]],
                check=True, capture_output=True, text=True,
            )
            intervals = [json.loads(line) for line in replay.stdout.splitlines()]
            self.assertTrue(intervals[-1]["final"])
            self.assertEqual(sum(interval["decoded"] for interval in intervals), 4)
            self.assertEqual(sum(interval["bytes"] for interval in intervals), 120)
            self.assertEqual(sum(interval["skipped"] for interval in intervals), 0)
            for protocol in ("17", "59"):
                self.assertEqual(sum(i["protocols"].get(protocol, 0) for i in intervals), 2)

            config = Path(folder) / "capture.conf"
            config.write_text(f"backend=pcap\npcap_file={capture}\ncpus=3\nqueue_capacity=1\nstats=true\n")
            configured = subprocess.run([command[0], "--config", str(config)],
                                        check=True, capture_output=True, text=True)
            self.assertIn("4 packets total", configured.stdout)
            self.assertIn("queue_high_water=1 ", configured.stderr)

            config.write_text("backend=hex-stdin\nqueue_capacity=0\n")
            invalid = subprocess.run([command[0], "--config", str(config)],
                                     capture_output=True, text=True)
            self.assertEqual(invalid.returncode, 1)
            self.assertIn("queue_capacity must be a positive integer", invalid.stderr)


if __name__ == "__main__":
    unittest.main()

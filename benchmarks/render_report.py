#!/usr/bin/env python3
"""Render a shareable HTML report from Google Benchmark JSON."""

import argparse
import html
import json
from pathlib import Path
import re
import statistics


def summarize(benchmarks):
    by_cpu = {}
    for row in benchmarks:
        if row.get("run_type") == "aggregate":
            continue
        match = re.match(r"capture/cpus:(\d+)/", row["name"])
        if match and "bytes_per_second" in row and "items_per_second" in row:
            by_cpu.setdefault(int(match[1]), []).append(row)
    if not by_cpu:
        raise ValueError("no capture runs with packet and byte rates found")

    rows = []
    for cpus, samples in sorted(by_cpu.items()):
        median = lambda key: statistics.median(sample[key] for sample in samples)
        rows.append((cpus, len(samples), median("items_per_second"),
                     median("bytes_per_second") * 8 / 1_000_000, median("queue_waits")))
    return rows


def render(data):
    rows = summarize(data["benchmarks"])
    fastest = max(rows, key=lambda row: row[2])
    best_rate = fastest[2]
    date = html.escape(data.get("context", {}).get("date", "")[:10])
    body = []
    for cpus, runs, packets, mbps, waits in rows:
        workers = f"{cpus - 1} decode workers" if cpus > 1 else "Inline decoding"
        body.append(f"""
          <tr>
            <th scope="row">{cpus}<small>{workers}</small></th>
            <td class="throughput"><strong>{packets:,.0f}</strong>
              <meter min="0" max="{best_rate}" value="{packets}"
                     aria-label="{packets:,.0f} packets per second"></meter></td>
            <td>{mbps:,.2f}</td>
            <td>{waits:,.0f}</td>
            <td>{runs}</td>
          </tr>""")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Packet Sniffer Performance</title>
<style>
  :root {{ color-scheme: light; font-family: system-ui, sans-serif; color: #15242e; background: #eef3f4; }}
  body {{ margin: 0; }}
  main {{ max-width: 960px; margin: auto; padding: clamp(1rem, 5vw, 4rem); }}
  header {{ margin-bottom: 2rem; }}
  h1 {{ font-size: clamp(2.1rem, 6vw, 4rem); line-height: 1.04; margin: .4rem 0 1rem; letter-spacing: -.045em; }}
  h2 {{ font-size: 1.25rem; margin: 0 0 .8rem; }}
  p {{ max-width: 72ch; line-height: 1.6; }}
  time, small {{ color: #4a626b; }}
  small {{ display: block; font-weight: normal; white-space: nowrap; }}
  section {{ background: #fff; border: 1px solid #cfdbdf; border-radius: .8rem; padding: clamp(.85rem, 3vw, 1.6rem); margin-bottom: 1rem; }}
  dl {{ display: flex; flex-wrap: wrap; gap: 1.5rem 3rem; margin: 0; }}
  dd {{ margin: .2rem 0 0; font-size: 1.8rem; font-weight: 700; color: #00635f; }}
  .table-wrap {{ overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; text-align: left; font-variant-numeric: tabular-nums; }}
  th, td {{ border-top: 1px solid #dce6e7; padding: .8rem .5rem; }}
  thead th {{ font-size: .88rem; color: #37545b; }}
  .throughput {{ min-width: 8rem; width: 34%; }}
  meter {{ display: block; width: 100%; height: .65rem; margin-top: .25rem; accent-color: #008477; }}
  code {{ overflow-wrap: anywhere; }}
</style>
</head>
<body>
<main>
  <header>
    <time datetime="{date}">{date}</time>
    <h1>Packet Sniffer Performance</h1>
    <p>A C++14 packet capture pipeline with offline replay, IPv4 and IPv6 decoding,
       and a configurable worker pool that hands batches to a dedicated writer.</p>
  </header>
  <section>
    <h2>Fastest measured configuration</h2>
    <dl>
      <div><dt>Packets per second</dt><dd>{fastest[2]:,.0f}</dd></div>
      <div><dt>IP throughput</dt><dd>{fastest[3]:,.2f} Mb/s</dd></div>
      <div><dt>Total capture threads</dt><dd>{fastest[0]}</dd></div>
    </dl>
  </section>
  <section>
    <h2>Scaling by thread count</h2>
    <p>Capture threads include one reader and any decode workers. With one
       thread, the reader also decodes. With four threads, one reads and
       three decode. Threaded packet output uses a separate writer. Metrics-only
       mode uses a separate reporter. The table counts readers and decode workers.</p>
    <div class="table-wrap">
      <table>
        <thead><tr><th scope="col">Threads</th><th scope="col">Packets/s</th>
          <th scope="col">IP Mb/s</th><th scope="col">Queue waits</th>
          <th scope="col">Runs</th></tr></thead>
        <tbody>{''.join(body)}</tbody>
      </table>
    </div>
  </section>
  <section>
    <h2>How it was measured</h2>
    <p>Google Benchmark replayed 16,384 synthetic 20-byte IPv4 packets per
       iteration through the capture pipeline and a counting sink. Values are
       medians across runs. Queue waits are average full-queue waits per
       iteration. IP throughput includes decoded IP headers and payload bytes.
       Timings include worker startup and shutdown. Live interface throughput
       can vary with packet sizes, socket behavior, and output costs.</p>
    <p>To reproduce, build <code>sniffer-benchmark</code> and run
       <code>./sniffer-benchmark --benchmark_repetitions=3 --benchmark_out=rates.json --benchmark_out_format=json</code>.</p>
  </section>
</main>
</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("benchmark_json", type=Path)
    parser.add_argument("output_html", type=Path)
    args = parser.parse_args()
    data = json.loads(args.benchmark_json.read_text(encoding="utf-8"))
    args.output_html.write_text(render(data), encoding="utf-8")


if __name__ == "__main__":
    main()

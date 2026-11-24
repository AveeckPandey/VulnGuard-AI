"""
VulnGuard AI - CLI Benchmark & Stress Testing Utility
Fires concurrent assessment requests against either the local development backend
or the live AWS Lambda serverless backend to measure latency, throughput, and error rates.

Usage:
  python scripts/run_stress_test.py --target local --concurrency 10 --requests 20
  python scripts/run_stress_test.py --target cloud --concurrency 5 --requests 10
"""
import sys
import time
import asyncio
import argparse
import statistics
from typing import List, Dict, Any
import httpx


TARGET_URLS = {
    "local": "http://127.0.0.1:8000/api/analyze",
    "cloud": "https://0n159e640h.execute-api.us-east-1.amazonaws.com/api/analyze",
}

SAMPLE_CVES = [
    "CVE-2021-44228",
    "CVE-2023-4863",
    "CVE-2024-6387",
    "CVE-2023-38606",
]


async def send_single_request(
    client: httpx.AsyncClient,
    url: str,
    cve_id: str,
    index: int,
    semaphore: asyncio.Semaphore,
) -> Dict[str, Any]:
    payload = {
        "cve_id": cve_id,
        "asset_criticality": "HIGH",
        "internet_exposure": "PUBLIC_FACING",
        "system_context": f"Benchmark worker task #{index}",
        "simulate_offline": False,
    }

    async with semaphore:
        t0 = time.perf_counter()
        try:
            resp = await client.post(url, json=payload, timeout=30.0)
            latency_ms = (time.perf_counter() - t0) * 1000.0
            return {
                "index": index,
                "cve_id": cve_id,
                "status_code": resp.status_code,
                "latency_ms": latency_ms,
                "success": resp.status_code in (200, 201),
                "error": None if resp.status_code in (200, 201) else resp.text[:120],
            }
        except Exception as e:
            latency_ms = (time.perf_counter() - t0) * 1000.0
            return {
                "index": index,
                "cve_id": cve_id,
                "status_code": 0,
                "latency_ms": latency_ms,
                "success": False,
                "error": str(e),
            }


async def run_benchmark(target: str, concurrency: int, total_requests: int):
    url = TARGET_URLS.get(target, target)
    print("=" * 70)
    print(" VULNGUARD AI - HIGH-CONCURRENCY STRESS & BENCHMARK SUITE")
    print("=" * 70)
    print(f" Target Endpoint : {url}")
    print(f" Concurrency Cap : {concurrency} parallel workers")
    print(f" Total Requests  : {total_requests}")
    print("=" * 70)

    semaphore = asyncio.Semaphore(concurrency)
    limits = httpx.Limits(max_keepalive_connections=concurrency, max_connections=concurrency * 2)

    async with httpx.AsyncClient(limits=limits) as client:
        start_time = time.perf_counter()

        tasks = [
            send_single_request(
                client=client,
                url=url,
                cve_id=SAMPLE_CVES[i % len(SAMPLE_CVES)],
                index=i + 1,
                semaphore=semaphore,
            )
            for i in range(total_requests)
        ]

        results = await asyncio.gather(*tasks)
        total_time = time.perf_counter() - start_time

    # Process metrics
    latencies = [r["latency_ms"] for r in results]
    successes = [r for r in results if r["success"]]
    failures = [r for r in results if not r["success"]]

    latencies.sort()
    p50 = statistics.median(latencies) if latencies else 0
    p90 = latencies[int(len(latencies) * 0.90)] if latencies else 0
    p95 = latencies[int(len(latencies) * 0.95)] if latencies else 0
    min_lat = min(latencies) if latencies else 0
    max_lat = max(latencies) if latencies else 0
    mean_lat = statistics.mean(latencies) if latencies else 0
    rps = total_requests / total_time if total_time > 0 else 0

    print("\nBENCHMARK RESULTS:")
    print("-" * 70)
    print(f" Total Time Taken      : {total_time:.2f} seconds")
    print(f" Throughput (RPS)      : {rps:.2f} requests/second")
    print(f" Success Count         : {len(successes)} / {total_requests} ({(len(successes)/total_requests)*100:.1f}%)")
    print(f" Failure Count         : {len(failures)} / {total_requests}")
    print("-" * 70)
    print("LATENCY DISTRIBUTION (round-trip per request):")
    print(f"  Min Latency          : {min_lat:.1f} ms")
    print(f"  P50 (Median)         : {p50:.1f} ms")
    print(f"  Mean Latency         : {mean_lat:.1f} ms")
    print(f"  P90 Latency          : {p90:.1f} ms")
    print(f"  P95 Latency          : {p95:.1f} ms")
    print(f"  Max Latency          : {max_lat:.1f} ms")
    print("-" * 70)

    if failures:
        print("\nSAMPLE ERRORS:")
        for f in failures[:3]:
            print(f" - Request #{f['index']} ({f['cve_id']}): {f['status_code']} -> {f['error']}")

    print("=" * 70)
    return len(failures) == 0


def main():
    parser = argparse.ArgumentParser(description="VulnGuard AI Concurrency & Stress Benchmark")
    parser.add_argument("--target", choices=["local", "cloud"], default="local", help="Target backend: local or cloud")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of concurrent workers")
    parser.add_argument("--requests", type=int, default=20, help="Total number of assessment requests")
    args = parser.parse_args()

    success = asyncio.run(run_benchmark(args.target, args.concurrency, args.requests))
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

from __future__ import annotations

import asyncio
import time

from src.net import async_connect


async def tcp_scan(
    ip: str,
    ports: list[int],
    timeout: float,
    concurrency: int,
) -> list[int]:
    sem = asyncio.Semaphore(concurrency)
    open_ports: list[int] = []
    total = len(ports)
    scanned = 0
    start = time.monotonic()

    async def probe(port: int) -> None:
        nonlocal scanned
        async with sem:
            _, is_open = await async_connect(ip, port, timeout)
            scanned += 1
            if is_open:
                open_ports.append(port)
                elapsed = time.monotonic() - start
                rate = scanned / elapsed if elapsed > 0 else 0
                print(
                    f"  \x1b[32m●\x1b[0m \x1b[1m{port}\x1b[0m/tcp  open"
                    f"  \x1b[90m({scanned}/{total} | {rate:.0f} ports/s)\x1b[0m"
                )

    tasks = [asyncio.create_task(probe(p)) for p in ports]
    await asyncio.gather(*tasks)

    elapsed = time.monotonic() - start
    print(
        f"\n  \x1b[90m{total} ports scanned in {elapsed:.1f}s"
        f" — {len(open_ports)} open\x1b[0m\n"
    )

    return sorted(open_ports)

from __future__ import annotations

import asyncio
import socket


async def resolve_host(host: str) -> str:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        if infos:
            return infos[0][4][0]
    except socket.gaierror:
        pass
    return host


async def async_connect(ip: str, port: int, timeout: float) -> tuple[int, bool]:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return port, True
    except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
        return port, False


async def read_banner_raw(ip: str, port: int, timeout: float) -> str:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return data.decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


async def send_and_read(ip: str, port: int, payload: bytes, timeout: float) -> str:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        writer.write(payload)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return data.decode("utf-8", errors="replace").strip()
    except Exception:
        return ""

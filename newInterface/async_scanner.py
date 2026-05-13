"""Scanner asyncio avec timeout adaptatif + enrichissement intégré."""
from __future__ import annotations

import asyncio
import socket
import statistics
import time
from typing import AsyncIterator, Iterable, Optional

from probes import probe_tcp, probe_udp_sync
from enrich import enrich_port, refresh_listening_cache, refresh_docker_cache


async def measure_rtt(host: str, samples: int = 4) -> Optional[float]:
    """Estime un RTT en tentant des connexions à des ports témoins.
    Tous fermés = OK, on mesure le temps de refus. Renvoie médiane en secondes."""
    test_ports = [80, 22, 443, 21, 3306]
    rtts: list[float] = []
    for p in test_ports[:samples]:
        t0 = time.perf_counter()
        try:
            await asyncio.wait_for(asyncio.open_connection(host, p), timeout=1.5)
        except asyncio.TimeoutError:
            continue
        except (ConnectionRefusedError, OSError):
            pass
        rtts.append(time.perf_counter() - t0)
    if not rtts:
        return None
    return statistics.median(rtts)


def adaptive_timeout(rtt: Optional[float], is_local: bool) -> float:
    if is_local:
        return 0.4
    if rtt is None:
        return 1.5
    return max(0.4, min(3.0, rtt * 6))


async def scan(
    target: str,
    ports: Iterable[int],
    *,
    udp: bool = False,
    concurrency: int = 400,
    is_local: bool = False,
    enrich: bool = True,
) -> AsyncIterator[dict]:
    """Scanne et yield un dict par port ouvert (résolu + enrichi)."""
    try:
        target_ip = socket.gethostbyname(target)
    except Exception as e:
        raise RuntimeError(f"Résolution impossible : {e}")

    rtt = None if is_local else await measure_rtt(target_ip)
    timeout = adaptive_timeout(rtt, is_local)

    if enrich and is_local:
        refresh_listening_cache()
        refresh_docker_cache()

    sem = asyncio.Semaphore(concurrency)
    ports_list = list(ports)

    async def _one(p: int) -> Optional[dict]:
        async with sem:
            try:
                res = await probe_tcp(target_ip, p, timeout=timeout)
            except Exception:
                return None
        if not res.get("open"):
            return None
        if enrich and is_local:
            try:
                en = enrich_port(p, "tcp")
                res["enrich"] = en
            except Exception:
                res["enrich"] = None
        return res

    tasks = [asyncio.create_task(_one(p)) for p in ports_list]
    for fut in asyncio.as_completed(tasks):
        r = await fut
        if r:
            yield r

    if udp:
        # UDP synchrone, dans un executor
        loop = asyncio.get_running_loop()
        udp_tasks = [
            loop.run_in_executor(None, probe_udp_sync, target_ip, p, max(timeout, 0.6))
            for p in ports_list[:1500]  # limiter
        ]
        for fut in asyncio.as_completed(udp_tasks):
            r = await fut
            if r and r.get("open"):
                if enrich and is_local:
                    try:
                        r["enrich"] = enrich_port(r["port"], "udp")
                    except Exception:
                        r["enrich"] = None
                yield r


async def scan_with_progress(
    target: str,
    ports: list[int],
    *,
    udp: bool = False,
    is_local: bool = False,
    on_found=None,
    on_progress=None,
    should_stop=None,
):
    """Wrapper avec callbacks pour intégration GUI."""
    total = len(ports) * (2 if udp else 1)
    done = 0
    found_count = 0

    async for res in scan(target, ports, udp=udp, is_local=is_local):
        if should_stop and should_stop():
            break
        found_count += 1
        if on_found:
            on_found(res)
        done += 5  # approx — on n'a pas une vraie progression port-par-port
        if on_progress:
            on_progress(min(done, total), total)

    if on_progress:
        on_progress(total, total)
    return found_count

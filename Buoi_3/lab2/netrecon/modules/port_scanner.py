import asyncio
from .log_utils import log


async def scan_port(target, port, semaphore):
    async with semaphore:
        writer = None
        log(f"TCP scan {target}:{port}")
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=1
            )
            log(f"Port {port} is open on {target}")
            print(f"[+] {port}/tcp open")
            return port
        except (OSError, asyncio.TimeoutError) as error:
            log(f"TCP scan {target}:{port}: {type(error).__name__}")
            return None
        finally:
            if writer is not None:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1)
                except (OSError, asyncio.TimeoutError):
                    pass


async def async_scan_ports(target, ports, rate_limit=100):
    """Quet TCP; gioi han so lan bat dau ket noi moi giay."""
    if rate_limit <= 0:
        raise ValueError("rate_limit must be positive")
    semaphore = asyncio.Semaphore(max(1, int(rate_limit)))
    tasks = []
    try:
        for port in ports:
            tasks.append(asyncio.create_task(scan_port(target, port, semaphore)))
            await asyncio.sleep(1 / rate_limit)
        results = await asyncio.gather(*tasks)
        return [port for port in results if port is not None]
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

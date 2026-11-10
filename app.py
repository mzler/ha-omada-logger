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
                await db.commit()
                logger.info(f"Database initialized at {self.db_path}")

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

        url = f"{self.base_url}/services/notify/{service_target}"
        payload = {
            "title": title,
            "message": message,
            "data": {
                "priority": "high",
                "tag": "omada-advisor",
                "push": {
                    "sound": "default",
                    "interruption-level": "critical" if severity == "CRITICAL" else "time-sensitive",
                },
                "actions": [
                    {
                        "action": "open_advisor",
                        "title": "Advisor öffnen",
                    }
                ],
            },
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
        self.prev_port_speeds: Dict[Tuple[str, int], int] = {}
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
                    # 500 on /api/v2/login (no prefix) almost always means v5+ controller.
                    # Reset and retry with fresh discovery.
                    if not self._api_prefix:
                        logger.warning(
                            "HTTP 500 on v4 login endpoint. Controller may be v5+. "
                            "Forcing re-discovery of omadacId..."
                        )
                        self._controller_version = None
                        self._api_prefix = ""
                        self._omadac_id = None
                        return False  # Will retry after re-discovery on next poll
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

    async def get_devices(self) -> List[Dict[str, Any]]:
        """GET /{prefix}/api/v2/sites/{omada_site}/devices"""
        path = f"{self._api_prefix}/api/v2/sites/{self.cfg.omada_site}/devices"
        data = await self._request_with_retry("GET", path)
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
        path = f"{self._api_prefix}/api/v2/sites/{self.cfg.omada_site}/cmd/devices/{device_mac}/clients"
        data = await self._request_with_retry("GET", path)
        if not data or data.get("errorCode", 0) != 0:
            return []
        result = data.get("result", {})
        if isinstance(result, list):
            return result
        return result.get("data", [])

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
                "message": "Controller offline or no devices returned",
            }
            return 0, []

        new_incidents: List[Dict[str, Any]] = []
        monitored_devices_count = len(devices)

        for dev in devices:
            dev_type = str(dev.get("type", "")).lower()
            dev_name = dev.get("name") or dev.get("model") or "Omada-Device"
            dev_mac = dev.get("mac") or dev.get("deviceMac") or "UNKNOWN-MAC"
            dev_ip = dev.get("ip") or dev.get("ipv4") or ""

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

                    # Update port history
                    if link_speed is not None:
                        self.prev_port_speeds[key] = int(link_speed)

            # -------------------------------------------------------------
            # Access Point Evaluation
            # -------------------------------------------------------------
            elif dev_type in ("ap", "eap"):
                # Status: 14 = Connected, other values = Disconnected / Isolated / Adoption required
                status = dev.get("status")
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

                # HEURISTIC 2: AP Disconnected / Isolated
                if status is not None and status != 14:
                    rec = (
                        f"Management-Kontakt zum Access Point {dev_name} verloren (Status {status}). "
                        f"PoE-Spannungsabfall durch Passthrough-Last oder Switch-Uplink prüfen."
                    )
                    raw_msg = f"Access Point offline or isolated: AP={dev_name} ({dev_mac}), Status={status}, IP={dev_ip}"
                    inc_id = await db_mgr.record_incident(
                        source_ip=dev_ip,
                        device_name=dev_name,
                        device_mac=dev_mac,
                        severity="CRITICAL",
                        category="INFORM_TIMEOUT",
                        raw_message=raw_msg,
                        action_recommendation=rec,
                    )
                    if inc_id:
                        inc_item = {
                            "id": inc_id,
                            "device_name": dev_name,
                            "severity": "CRITICAL",
                            "category": "INFORM_TIMEOUT",
                            "action_recommendation": rec,
                            "raw_message": raw_msg,
                        }
                        new_incidents.append(inc_item)
                        await ha_client.send_notification(
                            title="⚠️ Omada AP Isoliert / Offline",
                            message=f"Kritisch: {rec}",
                            severity="CRITICAL",
                            action=rec,
                        )

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
        """Parse raw syslog line and trigger heuristics"""
        # Extract potential MAC address or device identifier
        mac_match = MAC_ADDRESS_RE.search(message)
        device_mac = mac_match.group(0).upper().replace("-", ":") if mac_match else f"IP-{source_ip}"
        device_name = f"Omada-Device ({source_ip})"

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

    # Start background polling loop
    poller_task = asyncio.create_task(omada_polling_loop())

    # Initial sensor status sync
    initial_stats = await db_mgr.get_stats()
    await ha_client.sync_status_sensors(initial_stats)

    yield

    # Teardown
    poller_task.cancel()
    if transport:
        transport.close()
    logger.info("Omada Diagnostic Advisor background tasks terminated.")


app = FastAPI(
    title="Omada Diagnostic Advisor",
    description="Proaktive Fehlerfrüherkennung und Handlungsempfehlungen für TP-Link Omada Netzwerke",
    version="1.2.0",
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
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
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
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <header>
      <div class="title-area">
        <h1>
          <span>🛡️</span> Omada Diagnostic Advisor
        </h1>
        <p>Proaktives TP-Link Omada Netzwerk-Monitoring, Syslog-Heuristik & Handlungsempfehlungen</p>
      </div>
      <div class="header-actions">
        <button class="btn btn-primary" onclick="pollNow()" id="btn-scan">🔄 Jetzt prüfen</button>
        <button class="btn btn-secondary" onclick="resolveAll()">✓ Alle als behoben markieren</button>
        <a class="btn btn-secondary" href="{root_path}/api/incidents/export?format=csv" download>📥 CSV Export</a>
        <a class="btn btn-secondary" href="{root_path}/api/incidents/export?format=json" download>📥 JSON Export</a>
      </div>
    </header>

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
      <div class="card">
        <div class="status-card-header">
          <span>Syslog Empfangen</span>
          <span>📨</span>
        </div>
        <div class="status-card-value" id="card-syslog-val">0</div>
        <div class="status-card-desc">Port {config.syslog_port}/udp aktiv</div>
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
  </div>

  <script>
    const ROOT_PATH = "{root_path}";

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
        }} else if (activeWarn > 0) {{
          banner.className = "status-banner warn";
          bannerText.innerHTML = `<strong>WARNUNG:</strong> ${{activeWarn}} Warnung(en) aktiv. Netzwerkleistung ggf. beeinträchtigt.`;
          statusVal.innerHTML = `<span style="color:#f59e0b;">Warnung</span>`;
        }} else {{
          banner.className = "status-banner ok";
          bannerText.innerHTML = `<strong>OPTIMAL:</strong> Keine aktiven Netzwerkvorfälle. Alle überwachten Geräte arbeiten störungsfrei.`;
          statusVal.innerHTML = `<span style="color:#10b981;">Optimal</span>`;
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
              <td style="white-space:nowrap; color:var(--text-muted); font-size:0.8rem;">
                ${{inc.timestamp}}
              </td>
              <td>
                <span class="badge ${{badgeClass}}">${{inc.severity}}</span>
              </td>
              <td>
                <span class="badge badge-cat">${{inc.category || "GENERAL"}}</span>
              </td>
              <td>
                <strong>${{inc.device_name || "Unbekannt"}}</strong>
                <div style="font-size:0.75rem; color:var(--text-muted); font-family:monospace;">${{inc.device_mac || ""}}</div>
              </td>
              <td>
                <div class="action-box">
                  <strong>Empfehlung:</strong> ${{inc.action_recommendation}}
                </div>
                <div class="raw-msg" title="${{inc.raw_message || ''}}">
                  Detail: ${{inc.raw_message || 'N/A'}}
                </div>
              </td>
              <td>
                ${{isResolved 
                  ? '<span style="color:#10b981; font-weight:600; font-size:0.8rem;">✓ Behoben</span>' 
                  : '<span style="color:#ef4444; font-weight:600; font-size:0.8rem;">● Aktiv</span>'}}
              </td>
              <td>
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

    // Initial load & cyclic refresh
    loadStatus();
    loadTrends();
    loadIncidents();

    setInterval(() => {{
      loadStatus();
      loadIncidents();
    }}, 10000);
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

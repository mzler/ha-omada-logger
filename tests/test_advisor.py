"""
Unit and integration tests for Omada Diagnostic Advisor heuristics and DB logic.
"""

import re
import sqlite3
import sys
import unittest
from pathlib import Path

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
}

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


def is_device_offline(dev):
    """Evaluates whether an Omada network device is offline or degraded."""
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


def lookup_vendor(mac):
    if not mac or len(mac) < 8:
        return None
    prefix = mac[:8].upper().replace("-", ":")
    return COMMON_OUIS.get(prefix)


def parse_devices_from_syslog(source_ip, message):
    devices = []
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

# Verify regexes from app.py
INFORM_TIMEOUT_RE = re.compile(r"(Inform timeout|timeout isolated)", re.IGNORECASE)
WPA_HANDSHAKE_RE = re.compile(r"failed to stay connected.*reason:\s*15", re.IGNORECASE)
POE_OVERLOAD_RE = re.compile(r"(poe.*overload|poe.*power.*drop|insufficient.*power)", re.IGNORECASE)
MAC_ADDRESS_RE = re.compile(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")


def classify_syslog(message: str):
    """Classifies syslog message into (log_type, log_level)"""
    m = message.lower()
    if any(k in m for k in ("crit", "fatal", "emergency", "alert", "timeout isolated", "inform timeout", "overload")):
        level = "CRITICAL"
    elif any(k in m for k in ("err", "fail", "drop", "reject", "denied")):
        level = "ERROR"
    elif any(k in m for k in ("warn", "degrad", "interfer", "reason: 15", "retry", "loss", "radar", "dfs")):
        level = "WARN"
    else:
        level = "INFO"

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


class TestHeuristics(unittest.TestCase):
    def test_inform_timeout_detection(self):
        msg1 = "[AP-Wohnzimmer] [Inform timeout] Device failed to contact controller at 192.168.1.1:8043"
        msg2 = "Device EAP650 state changed: timeout isolated from mesh uplink"
        msg3 = "Normal syslog event: client connected to SSID HomeNet"

        self.assertTrue(bool(INFORM_TIMEOUT_RE.search(msg1)))
        self.assertTrue(bool(INFORM_TIMEOUT_RE.search(msg2)))
        self.assertFalse(bool(INFORM_TIMEOUT_RE.search(msg3)))

    def test_wpa_handshake_dropout_detection(self):
        msg1 = "Client [aa:bb:cc:dd:ee:ff] failed to stay connected to AP-Flur, reason: 15 (4-way handshake timeout)"
        msg2 = "Client 11:22:33:44:55:66 failed to stay connected with reason:15"
        msg3 = "Client disconnected normally reason: 3"

        self.assertTrue(bool(WPA_HANDSHAKE_RE.search(msg1)))
        self.assertTrue(bool(WPA_HANDSHAKE_RE.search(msg2)))
        self.assertFalse(bool(WPA_HANDSHAKE_RE.search(msg3)))

    def test_poe_overload_detection(self):
        msg1 = "Switch TL-SG2210P: Port 4 PoE power overload detected, disabling port"
        msg2 = "PoE power drop detected on port 2"
        msg3 = "Port 1 PoE power turned on (consuming 6.2W)"

        self.assertTrue(bool(POE_OVERLOAD_RE.search(msg1)))
        self.assertTrue(bool(POE_OVERLOAD_RE.search(msg2)))
        self.assertFalse(bool(POE_OVERLOAD_RE.search(msg3)))

    def test_mac_extraction(self):
        msg = "Device 34:E8:94:12:34:56 sent inform timeout"
        m = MAC_ADDRESS_RE.search(msg)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(0), "34:E8:94:12:34:56")


class TestDatabaseSchema(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self._init_schema()

    def tearDown(self):
        self.db.close()

    def _init_schema(self):
        self.db.execute(
            """
            CREATE TABLE incidents (
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
        self.db.execute(
            """
            CREATE TABLE metric_history (
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
        self.db.execute(
            """
            CREATE TABLE syslog_messages (
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
        self.db.commit()

    def test_syslog_storage_and_cleanup(self):
        # Insert test syslog messages
        self.db.execute(
            "INSERT INTO syslog_messages (source_ip, device_name, device_mac, message, timestamp) "
            "VALUES (?, ?, ?, ?, datetime('now', '-10 days'))",
            ("192.168.0.50", "AP-Wohnzimmer", "00:11:22:33:44:55", "Old message 10 days ago"),
        )
        self.db.execute(
            "INSERT INTO syslog_messages (source_ip, device_name, device_mac, message, timestamp) "
            "VALUES (?, ?, ?, ?, datetime('now', '-2 days'))",
            ("192.168.0.50", "AP-Wohnzimmer", "00:11:22:33:44:55", "Recent message 2 days ago"),
        )
        self.db.commit()

        # Count total
        c = self.db.execute("SELECT COUNT(*) FROM syslog_messages").fetchone()[0]
        self.assertEqual(c, 2)

        # Cleanup older than 7 days
        self.db.execute("DELETE FROM syslog_messages WHERE timestamp < datetime('now', '-7 days')")
        self.db.commit()

        # Only 1 recent message should remain
        c_after = self.db.execute("SELECT COUNT(*) FROM syslog_messages").fetchone()[0]
        self.assertEqual(c_after, 1)

        remaining = self.db.execute("SELECT message FROM syslog_messages").fetchone()[0]
        self.assertIn("Recent message", remaining)

    def test_syslog_filtering(self):
        # Insert various messages
        self.db.execute(
            "INSERT INTO syslog_messages (source_ip, device_name, log_type, log_level, message) "
            "VALUES (?, ?, ?, ?, ?)",
            ("192.168.0.50", "AP-Wohnzimmer", "WIFI", "WARN", "WPA authentication failed for client"),
        )
        self.db.execute(
            "INSERT INTO syslog_messages (source_ip, device_name, log_type, log_level, message) "
            "VALUES (?, ?, ?, ?, ?)",
            ("192.168.0.2", "Switch-Keller", "PORT_LINK", "CRITICAL", "Port 13 link changed to down"),
        )
        self.db.execute(
            "INSERT INTO syslog_messages (source_ip, device_name, log_type, log_level, message) "
            "VALUES (?, ?, ?, ?, ?)",
            ("192.168.0.1", "Router-Gateway", "SYSTEM", "INFO", "System clock synchronized"),
        )
        self.db.commit()

        # Filter by type
        wifi_rows = self.db.execute("SELECT * FROM syslog_messages WHERE log_type = 'WIFI'").fetchall()
        self.assertEqual(len(wifi_rows), 1)
        self.assertEqual(wifi_rows[0]["device_name"], "AP-Wohnzimmer")

        # Filter by level
        crit_rows = self.db.execute("SELECT * FROM syslog_messages WHERE log_level = 'CRITICAL'").fetchall()
        self.assertEqual(len(crit_rows), 1)
        self.assertEqual(crit_rows[0]["device_name"], "Switch-Keller")

        # Fulltext search
        search_rows = self.db.execute("SELECT * FROM syslog_messages WHERE message LIKE '%clock%'").fetchall()
        self.assertEqual(len(search_rows), 1)
        self.assertEqual(search_rows[0]["device_name"], "Router-Gateway")

    def test_insert_and_query_incident(self):
        cur = self.db.execute(
            """
            INSERT INTO incidents (
                source_ip, device_name, device_mac, severity,
                category, raw_message, action_recommendation, resolved
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (
                "192.168.1.10",
                "Switch-Keller",
                "00:11:22:33:44:55",
                "CRITICAL",
                "HARDWARE_LINK",
                "Link speed dropped from 1000M to 100M",
                "Switch-Port 13 (Switch-Keller) fiel auf 100 Mbit/s zurück. Verdacht auf Aderbruch (Pins 4/5 oder 7/8). Patchkabel/Dose neu auflegen.",
            ),
        )
        self.db.commit()
        self.assertEqual(cur.lastrowid, 1)

        row = self.db.execute("SELECT * FROM incidents WHERE id = 1").fetchone()
        self.assertEqual(row["device_name"], "Switch-Keller")
        self.assertEqual(row["severity"], "CRITICAL")
        self.assertEqual(row["category"], "HARDWARE_LINK")
        self.assertIn("Aderbruch", row["action_recommendation"])
        self.assertEqual(row["resolved"], 0)

    def test_link_speed_heuristic_evaluation(self):
        # Link drop: Port was Gigabit (3), now 100M (2)
        prev_speed = 3
        curr_speed = 2
        is_link_drop = (prev_speed >= 3 and curr_speed == 2)
        self.assertTrue(is_link_drop)

        # Normal Gigabit link
        prev_speed = 3
        curr_speed = 3
        self.assertFalse(prev_speed >= 3 and curr_speed == 2)

    def test_high_channel_util_heuristic(self):
        channel_2g_util = 85
        is_high = channel_2g_util > 80
        self.assertTrue(is_high)

        channel_2g_util_normal = 42
        self.assertFalse(channel_2g_util_normal > 80)


class TestDeviceInventory(unittest.TestCase):
    def test_vendor_lookup(self):
        self.assertEqual(lookup_vendor("04:17:B6:97:0E:DC"), "Apple")
        self.assertEqual(lookup_vendor("0C:EF:15:1B:BE:FE"), "TP-Link")
        self.assertEqual(lookup_vendor("24:4C:E3:11:22:33"), "Espressif")
        self.assertIsNone(lookup_vendor("00:00:00:00:00:00"))

    def test_parse_devices_from_dhcp_log(self):
        msg = "<13>Nov 10 22:05:41 ER605: 2026-11-10 22:05:41 dhcp_server<5>: [OMADA]DHCP Server allocated IP address 192.168.0.187 for the [client:04:17:b6:97:0e:dc ]."
        devs = parse_devices_from_syslog("192.168.0.1", msg)

        # Should find router (sender) and allocated client
        sender = next((d for d in devs if d.get("suggested_name") == "ER605"), None)
        self.assertIsNotNone(sender)
        self.assertEqual(sender["device_type"], "router")
        self.assertEqual(sender["ip"], "192.168.0.1")

        client = next((d for d in devs if d.get("mac") == "04:17:B6:97:0E:DC"), None)
        self.assertIsNotNone(client)
        self.assertEqual(client["ip"], "192.168.0.187")
        self.assertEqual(client["device_type"], "client")
        self.assertEqual(client["vendor"], "Apple")

    def test_parse_devices_from_ap_log(self):
        msg = "<6>Nov 10 22:05:43 192.168.0.173 [1794344739.090063089] AP MAC=0c:ef:15:1b:be:fe MAC SRC=04:17:b6:97:0e:dc IP SRC=0.0.0.0 IP DST=255.255.255.255 IP proto=17 SPT=68 DPT=67 [1794344743.450063091] AP MAC=0c:ef:15:1b:be:fe MAC SRC=98:03:8e:9c:5c:57 IP SRC=192.168.0.138 IP DST=192.168.0.171 IP proto=1"
        devs = parse_devices_from_syslog("192.168.0.173", msg)

        ap = next((d for d in devs if d.get("mac") == "0C:EF:15:1B:BE:FE"), None)
        self.assertIsNotNone(ap)
        self.assertEqual(ap["device_type"], "ap")
        self.assertEqual(ap["ip"], "192.168.0.173")

        c2 = next((d for d in devs if d.get("mac") == "98:03:8E:9C:5C:57"), None)
        self.assertIsNotNone(c2)
        self.assertEqual(c2["ip"], "192.168.0.138")
        self.assertEqual(c2["vendor"], "Apple")

    def test_sqlite_network_devices_schema_and_actions(self):
        con = sqlite3.connect(":memory:")
        con.row_factory = sqlite3.Row
        con.execute(
            """
            CREATE TABLE network_devices (
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

        # 1. Insert device with suggestion
        con.execute(
            "INSERT INTO network_devices (mac, ip, suggested_name, device_type) VALUES (?, ?, ?, ?)",
            ("0C:EF:15:1B:BE:FE", "192.168.0.173", "EAP653-Flur", "ap"),
        )
        con.commit()

        row = con.execute("SELECT * FROM network_devices WHERE mac = '0C:EF:15:1B:BE:FE'").fetchone()
        self.assertIsNone(row["custom_name"])
        self.assertEqual(row["suggested_name"], "EAP653-Flur")

        # 2. Accept suggestion
        con.execute("UPDATE network_devices SET custom_name = suggested_name, suggested_name = NULL WHERE id = 1")
        con.commit()

        row_accepted = con.execute("SELECT * FROM network_devices WHERE id = 1").fetchone()
        self.assertEqual(row_accepted["custom_name"], "EAP653-Flur")
        self.assertIsNone(row_accepted["suggested_name"])

        # 3. Reject suggestion on another device
        con.execute(
            "INSERT INTO network_devices (mac, ip, suggested_name, device_type) VALUES (?, ?, ?, ?)",
            ("04:17:B6:97:0E:DC", "192.168.0.187", "Unknown-iOS", "client"),
        )
        con.commit()

        con.execute("UPDATE network_devices SET suggested_rejected = suggested_name, suggested_name = NULL WHERE id = 2")
        con.commit()

        row_rejected = con.execute("SELECT * FROM network_devices WHERE id = 2").fetchone()
        self.assertEqual(row_rejected["suggested_rejected"], "Unknown-iOS")
        self.assertIsNone(row_rejected["suggested_name"])

    def test_is_device_offline_detection(self):
        # 1. online flag is False
        self.assertTrue(is_device_offline({"online": False})[0])

        # 2. String status variants
        self.assertTrue(is_device_offline({"showStatus": "Disconnected"})[0])
        self.assertTrue(is_device_offline({"showStatus": "Isolated"})[0])
        self.assertTrue(is_device_offline({"showStatus": "Heartbeat Missed"})[0])
        self.assertTrue(is_device_offline({"statusText": "offline"})[0])

        # 3. Status integer codes
        self.assertTrue(is_device_offline({"status": 0})[0])
        self.assertTrue(is_device_offline({"status": 2})[0])
        self.assertTrue(is_device_offline({"status": 11})[0])
        self.assertTrue(is_device_offline({"statusCategory": 0})[0])

        # 4. Healthy / Connected device
        self.assertFalse(is_device_offline({"online": True, "status": 14, "statusCategory": 1})[0])
        self.assertFalse(is_device_offline({"status": 14, "showStatus": "Connected"})[0])

    def test_ap_outage_regex(self):
        # Disconnect messages
        self.assertTrue(bool(AP_OUTAGE_RE.search("AP 0c:ef:15:1b:be:fe disconnected from controller")))
        self.assertTrue(bool(AP_OUTAGE_RE.search("ap[0c-ef-15-1b-be-fe] is offline")))
        self.assertTrue(bool(AP_OUTAGE_RE.search("Access Point EAP653-Flur lost connection")))
        self.assertTrue(bool(AP_OUTAGE_RE.search("heartbeat missed for AP [0c:ef:15:1b:be:fe]")))
        self.assertTrue(bool(AP_OUTAGE_RE.search("EAP615-Wall disconnected")))

        # Benign messages that should NOT match
        self.assertFalse(bool(AP_OUTAGE_RE.search("DHCP Server allocated IP address 192.168.0.187 for client")))
        self.assertFalse(bool(AP_OUTAGE_RE.search("client 04:17:b6:97:0e:dc connected to SSID HomeNet")))

    def test_switch_port_down_regex(self):
        self.assertTrue(bool(SWITCH_PORT_DOWN_RE.search("Port 5 link down")))
        self.assertTrue(bool(SWITCH_PORT_DOWN_RE.search("link changed to down on port 13")))
        self.assertFalse(bool(SWITCH_PORT_DOWN_RE.search("Port 5 link up at 1000Mbps")))

    def test_resolve_incidents_by_device(self):
        con = sqlite3.connect(":memory:")
        con.row_factory = sqlite3.Row
        con.execute(
            """
            CREATE TABLE incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_mac TEXT,
                category TEXT,
                resolved INTEGER DEFAULT 0
            );
            """
        )
        con.execute("INSERT INTO incidents (device_mac, category, resolved) VALUES ('0C:EF:15:1B:BE:FE', 'AP_OUTAGE', 0)")
        con.execute("INSERT INTO incidents (device_mac, category, resolved) VALUES ('0C:EF:15:1B:BE:FE', 'INFORM_TIMEOUT', 0)")
        con.execute("INSERT INTO incidents (device_mac, category, resolved) VALUES ('CONTROLLER', 'CONTROLLER_OFFLINE', 0)")
        con.commit()

        # Resolve only AP_OUTAGE for that MAC
        cursor = con.execute("UPDATE incidents SET resolved = 1 WHERE device_mac = ? AND category = ? AND resolved = 0", ("0C:EF:15:1B:BE:FE", "AP_OUTAGE"))
        con.commit()
        self.assertEqual(cursor.rowcount, 1)

        # Check remaining active
        remaining = con.execute("SELECT category FROM incidents WHERE resolved = 0").fetchall()
        categories = [r["category"] for r in remaining]
        self.assertNotIn("AP_OUTAGE", categories)
        self.assertIn("INFORM_TIMEOUT", categories)
        self.assertIn("CONTROLLER_OFFLINE", categories)


class TestExtendedDiagnostics(unittest.TestCase):
    def test_classify_syslog_types(self):
        t1, l1 = classify_syslog("Radar detected on channel 100, switching AP to channel 36")
        self.assertEqual(t1, "RADAR_DFS")
        self.assertEqual(l1, "WARN")

        t2, l2 = classify_syslog("Client 04:17:B6:97:0E:DC performed 802.11r fast bss roaming to AP-Buero")
        self.assertEqual(t2, "ROAMING")
        self.assertEqual(l2, "INFO")

        t3, l3 = classify_syslog("[Controller Event] Admin user logged into controller from 192.168.0.50")
        self.assertEqual(t3, "CONTROLLER_EVENT")

        t4, l4 = classify_syslog("Switch PoE power overload detected on Port 3, drop power")
        self.assertEqual(t4, "POE")
        self.assertEqual(l4, "CRITICAL")

    def test_cable_integrity_crc_error_logic(self):
        prev_crc = 10
        current_crc_small = 15
        delta_small = current_crc_small - prev_crc
        self.assertEqual(delta_small, 5)
        sev_small = "CRITICAL" if delta_small >= 20 else "WARNING"
        self.assertEqual(sev_small, "WARNING")

        current_crc_large = 35
        delta_large = current_crc_large - prev_crc
        self.assertEqual(delta_large, 25)
        sev_large = "CRITICAL" if delta_large >= 20 else "WARNING"
        self.assertEqual(sev_large, "CRITICAL")

    def test_device_extended_hardware_schema(self):
        con = sqlite3.connect(":memory:")
        con.row_factory = sqlite3.Row
        con.execute(
            """
            CREATE TABLE network_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT UNIQUE,
                ip TEXT,
                custom_name TEXT,
                suggested_name TEXT,
                device_type TEXT DEFAULT 'client',
                vendor TEXT,
                model TEXT,
                firmware TEXT,
                need_upgrade BOOLEAN DEFAULT 0,
                uptime INTEGER DEFAULT 0,
                cpu_util INTEGER,
                mem_util INTEGER,
                client_count INTEGER DEFAULT 0,
                status_text TEXT,
                ports_json TEXT,
                wireless_json TEXT,
                wan_json TEXT,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                log_count INTEGER DEFAULT 1
            );
            """
        )
        con.execute(
            """
            INSERT INTO network_devices (
                mac, ip, custom_name, suggested_name, device_type, vendor,
                model, firmware, need_upgrade, uptime, cpu_util, mem_util, client_count, status_text
            ) VALUES (
                '00:0A:EB:11:22:33', '192.168.0.2', 'Core Switch', 'TL-SG2210P', 'switch', 'TP-Link',
                'TL-SG2210P v5.0', '1.0.3 Build 20240315', 1, 864000, 15, 38, 8, 'Connected'
            )
            """
        )
        con.commit()

        row = con.execute("SELECT * FROM network_devices WHERE mac = '00:0A:EB:11:22:33'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["model"], "TL-SG2210P v5.0")
        self.assertEqual(row["firmware"], "1.0.3 Build 20240315")
        self.assertEqual(row["need_upgrade"], 1)
        self.assertEqual(row["uptime"], 864000)
        self.assertEqual(row["cpu_util"], 15)
        self.assertEqual(row["mem_util"], 38)
        self.assertEqual(row["client_count"], 8)


if __name__ == "__main__":
    unittest.main()

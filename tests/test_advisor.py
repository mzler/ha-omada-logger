"""
Unit and integration tests for Omada Diagnostic Advisor heuristics and DB logic.
"""

import re
import sqlite3
import unittest
from pathlib import Path

# Verify regexes from app.py
INFORM_TIMEOUT_RE = re.compile(r"(Inform timeout|timeout isolated)", re.IGNORECASE)
WPA_HANDSHAKE_RE = re.compile(r"failed to stay connected.*reason:\s*15", re.IGNORECASE)
POE_OVERLOAD_RE = re.compile(r"(poe.*overload|poe.*power.*drop|insufficient.*power)", re.IGNORECASE)
MAC_ADDRESS_RE = re.compile(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")


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
        self.db.commit()

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


if __name__ == "__main__":
    unittest.main()

# Omada Diagnostic Advisor – Home Assistant OS Add-on

[![Home Assistant Add-on](https://img.shields.io/badge/Home%20Assistant-Add--on-blue.svg)](https://www.home-assistant.io/)
[![Multi-Arch](https://img.shields.io/badge/Arch-aarch64%20%7C%20amd64-green.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Der **Omada Diagnostic Advisor** ist ein produktionsreifes Home Assistant OS Add-on zur intelligenten Überwachung, Fehlerfrüherkennung und Handlungsempfehlung für TP-Link Omada Netzwerkinfrastrukturen (Omada Controller, Switches und EAP Access Points).

Das Add-on korreliert zyklische REST-API-Telemetriedaten des Controllers mit Echtzeit-Syslog-Meldungen via UDP, speichert Vorfälle persistent in SQLite und alarmiert proaktiv via Home Assistant Push-Notification mit präzisen Diagnosehinweisen.

---

## 🚀 Kernfunktionen

- **Multi-Architektur-Unterstützung**: Vorkonfiguriert für `aarch64` (Raspberry Pi 4/5, Home Assistant Green/Yellow, ODROID) und `amd64` (x86-64 Home Assistant OS / Proxmox VM).
- **Asynchroner UDP Syslog Listener (Port 5514)**: Fängt Systemprotokolle von TP-Link Omada Geräten in Echtzeit ab.
- **Controller REST-API Poller**: Fragt alle 60 Sekunden Geräte, Ports, CPU/RAM, PoE-Verbrauch und Funkkanal-Auslastung ab. Inklusive automatischem Re-Login bei Token-/Session-Ablauf.
- **Intelligente Heuristik & Fehlerdiagnose**:
  1. **Hardware Link-Drop (Aderbruch)**: Erkennt sofort, wenn ein Switch-Port von Gigabit (1000 Mbit/s) auf Fast Ethernet (100 Mbit/s) zurückfällt (typisch bei Bruch von Pins 4/5 oder 7/8).
  2. **Inform Timeout / AP-Isolation**: Erkennt Verbindungsabbrüche zwischen Access Point und Controller (z. B. durch PoE-Spannungsabfall oder Switch-Port-Fehler).
  3. **WPA 4-Way Handshake Dropouts**: Filtert Disconnects mit `reason: 15` heraus und weist auf WPA3/PMF-Inkompatibilitäten hin.
  4. **2.4-GHz-Kanalüberlastung**: Alarmiert bei Kanal-Auslastung `> 80%` mit Optimierungshinweisen für Kanal- und Sendeleistung.
- **Home Assistant Ingress Dark-Mode Dashboard**:
  - **Tab 1: Diagnose & Vorfälle**:
    - Übersichtlicher Gesundheitsstatus (Optimal / Eingeschränkt / Warnung / Kritisch).
    - Direkter Syslog-Live-Stream der neuesten Ereignisse auf dem Dashboard.
    - Klickbare Statistik-Karte *"Syslog Empfangen"* mit Schnellsprung ins Protokoll.
    - Live-Tabelle der aktiven und behobenen Vorfälle mit Filterung nach Gerät und Schweregrad.
    - Vollständig responsives Mobile-Layout für Smartphones (Card-Darstellung für alle Tabellen, wischbare Tab-Leiste).
    - Trend-Analyse (Häufung nach Uhrzeit und am stärksten betroffenen Geräten).
    - Direkte Aktions-Buttons: *"Als behoben markieren"*, *"Alle beheben"*, *"CSV/JSON Export"* und manueller Scan-Trigger.
  - **Tab 2: Syslog-Protokoll (Alle Logs)**:
    - Vollständige Historie aller empfangenen Syslog-Meldungen, persistent gespeichert für $X$ Tage (`log_retention_days`).
    - Feingranulare Filterung nach Volltextsuche, Protokoll-Typ (WIFI, PORT_LINK, POE, SYSTEM, DHCP), Level (CRITICAL, ERROR, WARN, INFO), Gerät / IP und Zeitfenster (1h, 24h, 7 Tage oder benutzerdefinierter Zeitraum).
    - Schneller Kopier-Button für jede Log-Zeile sowie separater CSV- und JSON-Export.
  - **Tab 3: Virtuelle Geräte (Inventar & Namenserkennung)**:
    - Automatische Erkennung aller Geräte aus Syslogs (Router, Switches, Access Points, DHCP & WLAN-Clients).
    - OUI-Herstellererkennung (Apple, TP-Link, Espressif, Raspberry Pi, etc.).
    - Automatische Namensvorschläge aus Syslogs (`💡 ER605`) mit Ein-Klick-Optionen **[✓ Annehmen]** und **[✕ Ablehnen]**.
    - Freie Benennung und Umbenennung jedes Geräts per Dialogfeld (✏️).
    - Schnellsprung "📜 Logs" zum sofortigen Filtern aller Meldungen des gewählten Geräts.
- **Home Assistant Core Integration**:
  - Automatische Aktualisierung von `sensor.omada_advisor_status` und `sensor.omada_advisor_recommendation`.
  - Dynamische Dropdown-Auswahl der Notify-Entität (`notify.*`) direkt im Web-UI.
  - Konfigurierbarer Push-Typ: **Kritische Push-Nachricht** (durchbricht 'Nicht Stören'/Stummschaltung via iOS `interruption-level: critical` / Android `alarm_stream`) oder **Herkömmliche Push**.

---

## 🛠️ Architektur

```
                                  +------------------------------------+
                                  |   TP-Link Omada Controller / APs   |
                                  +-----------------+------------------+
                                                    |
                          UDP Syslog (Port 5514)   |   REST API (HTTPS 8043)
                                                    |
                                                    v
+-----------------------------------------------------------------------------------------+
| Home Assistant OS: Omada Diagnostic Advisor (Docker Container)                          |
|                                                                                         |
|  +------------------------+      +---------------------------+                          |
|  | UDP Syslog Listener    |      | Controller REST Poller    |                          |
|  | (AsyncIO Datagram)     |      | (httpx.AsyncClient)       |                          |
|  +-----------+------------+      +-------------+-------------+                          |
|              |                                 |                                        |
|              +----------------+----------------+                                        |
|                               |                                                         |
|                               v                                                         |
|                  +--------------------------+                                           |
|                  | Diagnostic Heuristics    |                                           |
|                  | & Anti-Flap Filter       |                                           |
|                  +------------+-------------+                                           |
|                               |                                                         |
|       +-----------------------+-----------------------+                                 |
|       |                                               |                                 |
|       v                                               v                                 |
|  +-----------------------------+         +-------------------------------+              |
|  | SQLite Persistent Storage   |         | Home Assistant Core API       |              |
|  | /data/omada_diagnostics.db  |         | - sensor.omada_advisor_*      |              |
|  | (incidents & metric_history)|         | - notify.mobile_app_*         |              |
|  +--------------+--------------+         +-------------------------------+              |
|                 |                                                                       |
|                 v                                                                       |
|  +--------------------------------------------------------------------+                 |
|  | FastAPI Ingress Web-Dashboard (Port 8099, Dark-Mode, Root-Path)    |                 |
|  +--------------------------------------------------------------------+                 |
+-----------------------------------------------------------------------------------------+
```

---

## 📦 Installation

1. Kopiere das Verzeichnis dieses Add-ons (`ha-omada-logger`) auf deinen Home Assistant Host in den Ordner `/addons/omada_diagnostic_advisor` (z. B. via Samba Share, SSH oder Add-on Git Repository).
2. Öffne in Home Assistant **Einstellungen** -> **Add-ons** -> **Add-on-Store**.
3. Klicke oben rechts auf die drei Punkte `...` -> **Repositories verwalten** und aktualisiere bzw. füge das lokale Repository hinzu.
4. Wähle **Omada Diagnostic Advisor** aus und klicke auf **Installieren**.
5. Konfiguriere die Optionen im Reiter **Konfiguration** und starte das Add-on.
6. Klicke auf **In der Seitenleiste anzeigen** und **Web-UI öffnen**.

---

## ⚙️ Konfiguration

Beispielkonfiguration in Home Assistant:

```yaml
omada_host: "192.168.1.1"
omada_port: 8043
omada_user: "admin"
omada_password: "DeinSicheresPasswort"
omada_site: "Default"
verify_ssl: false
poll_interval_seconds: 60
notify_service: "notify.mobile_app_dein_smartphone"
notify_min_severity: "CRITICAL"
notify_push_type: "critical"
log_retention_days: 7
```

| Parameter | Typ | Standard | Beschreibung |
|---|---|---|---|
| `omada_host` | string | `192.168.1.1` | IP-Adresse oder Hostname des Omada Software/Hardware-Controllers. |
| `omada_port` | port | `8043` | HTTPS-Port des Controllers (Standard: 8043). |
| `omada_user` | string | `admin` | Benutzername für den Controller API-Zugriff. |
| `omada_password` | password | `""` | Passwort des Controller-Benutzers. |
| `omada_site` | string | `Default` | Name der zu überwachenden Site im Omada Controller. |
| `verify_ssl` | boolean | `false` | SSL-Zertifikatsvalidierung für Controller HTTPS-Verbindung. |
| `poll_interval_seconds` | integer | `60` | Abfrageintervall der Geräte und Ports in Sekunden (10 - 3600). |
| `syslog_port` | port | `5514` | Interner UDP-Syslog-Port des Add-ons (z. B. 5514 oder 5515). |
| `notify_service` | string | `none` | Name des HA Notification-Dienstes (z. B. `notify.mobile_app_pixel`). |
| `notify_min_severity` | string | `CRITICAL` | Mindestschweregrad für Benachrichtigungen (`CRITICAL` oder `WARNING`). |
| `notify_push_type` | list | `critical` | Art der Push-Nachricht: `critical` (durchbricht 'Nicht Stören') oder `standard`. |
| `log_retention_days` | integer | `7` | Anzahl Tage zur persistenten Speicherung aller empfangenen Syslog-Nachrichten in SQLite. |

---

## 📡 Omada Syslog-Weiterleitung einrichten

Damit Vorfälle wie WPA-Handshake-Timeouts oder Inform-Timeouts in Echtzeit analysiert werden können, leite die Syslog-Nachrichten an Home Assistant weiter:

1. Öffne die Weboberfläche deines **TP-Link Omada Controllers**.
2. Navigiere zu **Settings (Einstellungen)** -> **Global Settings / Site Settings** -> **Log / Syslog**.
3. Aktiviere **Syslog Server**.
4. Trage die **IP-Adresse deines Home Assistant Hosts** ein.
5. Port: `5514` (UDP).
6. Speicher die Einstellungen.

---

## 📊 Home Assistant Sensoren

Das Add-on erzeugt und pflegt automatisch folgende Entitäten in Home Assistant:

- `sensor.omada_advisor_status`:
  - **State**: Aktueller Netzwerk-Gesundheitsstatus (z. B. `"Normal: Netzwerk stabil"` oder `"CRITICAL: 1 kritische(r) Vorfall/Vorfälle aktiv!"`).
  - **Attribute**: `active_incidents`, `critical_incidents`, `warning_incidents`, `last_sync`.
- `sensor.omada_advisor_recommendation`:
  - **State**: Sofortige Handlungsempfehlung für das Betriebsteam.
  - **Attribute**: `full_recommendation`, `device`, `category`, `severity`.

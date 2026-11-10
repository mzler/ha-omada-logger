# Changelog

Alle nennenswerten Änderungen an diesem Add-on werden in dieser Datei dokumentiert.

## [1.4.0] - 2026-11-10
### Hinzugefügt
- **Persistente Syslog-Speicherung & Retention-Policy**:
  - Alle über Port 5514 empfangenen Syslog-Meldungen werden ab sofort persistent in SQLite in der Tabelle `syslog_messages` gespeichert.
  - Konfigurierbare Speicherdauer in Tagen (`log_retention_days`, Standard: 7 Tage). Ältere Logs werden automatisch alle 6 Stunden und beim Start bereinigt.
- **Kritische vs. Herkömmliche Push-Benachrichtigung**:
  - Im Einstellungsdialog kann nun zwischen **🚨 Kritischer Push-Alarm** (durchbricht iOS & Android 'Nicht Stören'/Stummschaltung) und **🔔 Herkömmlicher Push** (Standard-Benachrichtigung) gewählt werden.
  - Automatische Konfiguration von `interruption-level: critical`, `sound.critical: 1` für iOS und `channel: alarm_stream`, `priority: high` für Android.
- **Feingranularer Syslog-Viewer (Neuer Dashboard-Tab "📜 Syslog-Protokoll")**:
  - Tab-Navigation im Dashboard zwischen "🛡️ Diagnose & Vorfälle" und "📜 Syslog-Protokoll".
  - Volltext-Suche in Meldungstext und Quell-IP.
  - Filter nach Protokoll-Typ (WLAN & Roaming, Port & Link-Drop, PoE, System & Reboot, DHCP, Allgemein).
  - Filter nach Schweregrad (CRITICAL, ERROR, WARN, INFO).
  - Dynamisches Dropdown für alle meldenden Netzwerkgeräte.
  - Zeitfenster-Filter (Letzte Stunde, Letzte 24h, Letzte 7 Tage oder benutzerdefinierter Datumsbereich von/bis).
  - Zeilenbegrenzung (50, 100, 250, 500 Zeilen).
  - Ein-Klick-Kopierbutton für jede Nachricht in die Zwischenablage.
  - Eigener CSV- und JSON-Export für alle gefilterten Syslog-Logs.

## [1.3.0] - 2026-11-10
### Hinzugefügt
- **Dynamische Notify-Entitätsauswahl via Dropdown**: Im Ingress Web-Dashboard gibt es nun einen "🔔 Benachrichtigung"-Button.
- Das Dropdown lädt automatisch alle in Home Assistant registrierten `notify.*`-Dienste (z. B. `notify.mobile_app_<smartphone>`, `notify.persistent_notification`).
- Direkter "🧪 Test senden"-Button im Dashboard zur sofortigen Überprüfung der Push-Benachrichtigung.
- Einstellungen werden direkt übernommen und persistent in `/data/options.json` gespeichert.

## [1.2.1] - 2026-11-10
### Behoben
- **Automatischer Fallback auf Port 443 (NGINX)**: Bei neueren Omada Controllern (v6.x) schlägt der Login auf Port 8043 mit HTTP 500 fehl, da die NGINX-Reverse-Proxy-Schicht auf Port 443 liegt. Das Add-on erkennt diesen Zustand nun vollautomatisch und switcht nahtlos auf Port 443 um.

## [1.2.0] - 2026-11-10
### Behoben
- **Omada Controller v5+ API-Kompatibilität (HTTP 500 Login-Fix)**: Der API-Client erkennt nun automatisch die Controller-Version via `GET /api/info`, liest die `omadacId` aus und stellt alle Requests korrekt mit dem nötigen URL-Präfix `/{omadacId}/api/v2/...` (v5+) bzw. ohne Präfix `/api/v2/...` (v4) aus.
- `FastAPIDeprecationWarning` behoben: `Query(regex=...)` → `Query(pattern=...)` für FastAPI 0.115+.

## [1.1.0] - 2026-11-10
### Hinzugefügt
- Offizielles Add-on Icon (`icon.png`), Logo (`logo.png`) und Vektor-Grafik (`icon.svg`).
- Flexibler Syslog-Port: Portbindung in `config.yaml` auf `null` gesetzt, um Portkonflikte (`Port 5514 is already in use`) beim Start zu verhindern.
- Der Host-Port kann nun im Home Assistant Add-on Dashboard unter "Netzwerk" beliebig vergeben werden (z. B. 5515 oder 5516).
- Option `syslog_port` im Options-Schema hinzugefügt.
- Fehlerresistentes Binden des UDP-Sockets: Selbst bei lokalen Port-Kollisionen starten REST-Poller und Web-Dashboard unterbrechungsfrei weiter.

## [1.0.0] - 2026-11-10
### Hinzugefügt
- Asynchroner UDP Syslog-Server auf Port 5514 zur Verarbeitung von Omada AP- und Switch-Logs.
- Omada Controller REST-API Poller mit CSRF-Token-Handhabung, Cookie-Session-Management und automatischem Re-Login.
- Hardware-Degradierungs-Heuristik: Erkennt Link-Drops von 1000 Mbit/s auf 100 Mbit/s (Aderbruch an Pins 4/5 oder 7/8).
- Erkennung von Management-Timeouts (`Inform timeout|timeout isolated`) und Access Point Verbindungsverlusten.
- WLAN 4-Way Handshake Timeout Erkennung (`reason: 15`) zur Diagnose von WPA3/PMF-Problemen.
- Überwachung der 2.4-GHz-Kanalinterferenz (`> 80%`).
- Persistente SQLite-Datenbank unter `/data/omada_diagnostics.db` für `incidents` und `metric_history`.
- Home Assistant Ingress Dark-Mode Dashboard auf Port 8099 mit dynamischem `root_path`-Handling.
- Vorfall-Filter, Behebungsfunktion und Datenexport als CSV und JSON.
- Anbindung an die Home Assistant Supervisor API zur Aktualisierung von `sensor.omada_advisor_status` und `sensor.omada_advisor_recommendation`.
- Konfigurierbare Mobile-Push-Benachrichtigungen mit Schweregrad-Filter.
- Multi-Architektur-Builds für `aarch64` und `amd64`.

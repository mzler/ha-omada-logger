# Changelog

Alle nennenswerten Änderungen an diesem Add-on werden in dieser Datei dokumentiert.

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

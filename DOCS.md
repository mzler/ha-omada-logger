# Omada Diagnostic Advisor – Dokumentation

## Inhaltsverzeichnis
1. [Überblick](#überblick)
2. [Heuristiken und Diagnose-Regeln](#heuristiken-und-diagnose-regeln)
3. [Datenbank & Persistenz](#datenbank--persistenz)
4. [Home Assistant Ingress Dashboard](#home-assistant-ingress-dashboard)
5. [Automatisierungen in Home Assistant](#automatisierungen-in-home-assistant)
6. [Fehlerbehebung (Troubleshooting)](#fehlerbehebung-troubleshooting)

---

## Überblick
Der Omada Diagnostic Advisor schließt die Lücke zwischen reiner Status-Anzeige und proaktiver Netzwerk-Instandhaltung. Durch die Kombination von:
- zyklischer REST-API-Abfrage (Portzustände, Link-Geschwindigkeiten, Funküberlastung)
- asynchronem UDP-Syslog-Empfang auf Port 5514
- automatischer Entprellung (Deduplizierung) von Events
bietet das Add-on sofort verwertbare Handlungsempfehlungen bei Hardware-Defekten und Funkstörungen.

---

## Heuristiken und Diagnose-Regeln

### 1. Hardware Link-Drop (Aderbruch-Erkennung)
- **Kategorie**: `HARDWARE_LINK`
- **Schweregrad**: `CRITICAL`
- **Bedingung**: Ein Switch-Port, der zuvor mit Gigabit (1000 Mbit/s, `linkSpeed == 3`) synchronisiert war oder als Uplink/AP konfiguriert ist, fällt auf 100 Mbit/s (`linkSpeed == 2`) zurück.
- **Hintergrund**: 1000BASE-T (Gigabit) benötigt alle 4 Adernpaare (Pins 1/2, 3/6, 4/5 und 7/8). Wenn eines der Paare 4/5 oder 7/8 unterbrochen wird (z. B. durch Knick, schlechten Kontakt in der Netzwerkdose oder defektes Patchkabel), schlägt die Gigabit-Auto-Negotiation fehl und der Switch fällt laut IEEE 802.3 auf 100BASE-TX (Fast Ethernet) zurück.
- **Handlungsempfehlung**: *"Switch-Port {port} ({device_name}) fiel auf 100 Mbit/s zurück. Verdacht auf Aderbruch (Pins 4/5 oder 7/8). Patchkabel/Dose neu auflegen."*

### 2. Inform Timeout / AP-Isolation
- **Kategorie**: `INFORM_TIMEOUT`
- **Schweregrad**: `CRITICAL`
- **Bedingung**: Syslog enthält `(Inform timeout|timeout isolated)` oder Controller meldet AP-Status `!= 14`.
- **Hintergrund**: Der Access Point kann den Controller nicht mehr per HTTP/HTTPS erreichen. Häufigste Ursachen sind Überlastung des PoE-Budgets (Spannungseinbruch bei Lastspitzen), Kabelprobleme auf der Zuleitung oder fehlerhafte VLAN-Zuordnungen.
- **Handlungsempfehlung**: *"Management-Kontakt verloren. PoE-Spannungsabfall durch Passthrough-Last oder Switch-Uplink prüfen."*

### 3. WPA Handshake Timeout (Reason 15)
- **Kategorie**: `WIFI_HANDSHAKE`
- **Schweregrad**: `WARNING`
- **Bedingung**: Syslog enthält `failed to stay connected.*reason:\s*15`.
- **Hintergrund**: Ein WLAN-Client konnte den 4-Way EAPOL-Handshake innerhalb des vorgegebenen Zeitfensters nicht abschließen. Dies tritt sehr häufig bei älteren IoT-Geräten auf, wenn WPA3 Transition Mode oder Protected Management Frames (PMF) aktiviert sind.
- **Handlungsempfehlung**: *"WPA 4-Way Handshake Timeout. Client-Inkompatibilität mit WPA3/PMF prüfen."*

### 4. 2.4-GHz-Kanal-Interferenz
- **Kategorie**: `INTERFERENCE`
- **Schweregrad**: `WARNING`
- **Bedingung**: Kanal-Auslastung (`channel2gUtil`) übersteigt 80 %.
- **Hintergrund**: Hohe Belegung durch Nachbarnetzwerke, Bluetooth, Mikrowellen oder Babyphone. Führt zu massiven Paketverlusten und Latenzproblemen im Smart Home (z. B. Zigbee-Koexistenz).
- **Handlungsempfehlung**: *"2.4 GHz Interferenz extrem hoch (>80%). Funkkanal fest auf 1, 6 oder 11 fixieren oder Sendeleistung reduzieren."*

---

## Datenbank & Persistenz

Alle Vorfälle und Metriken werden in SQLite unter `/data/omada_diagnostics.db` gespeichert. Durch das Speichern im Home Assistant Verzeichnis `/data` bleiben die Daten auch bei Add-on-Updates oder Neustarts vollständig erhalten.

### Tabelle `incidents`:
```sql
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
```

### Tabelle `metric_history`:
```sql
CREATE TABLE metric_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    device_name TEXT,
    link_speed INTEGER,
    poe_power_w REAL,
    channel_util_2g INTEGER,
    channel_util_5g INTEGER
);
```

---

## Home Assistant Ingress Dashboard

Das Dashboard ist direkt über die Home Assistant Seitenleiste via Ingress erreichbar:
- **Port**: 8099 (intern im Docker-Container, durch HA Ingress abgesichert).
- **Dark Mode**: Ermüdungsfreies Design abgestimmt auf Home Assistant.
- **Filter**: Filterung nach Schweregrad (Alle / Kritisch / Warnung) und Freitextsuche nach Gerät oder MAC.
- **Export**: Vorfälle können jederzeit mit einem Klick als CSV oder JSON heruntergeladen werden.
- **Beheben**: Einzelne Vorfälle oder alle Vorfälle können mit einem Klick als "Behoben" markiert werden, wodurch sich der globale Status wieder auf "Optimal" zurücksetzt.

---

## Automatisierungen in Home Assistant

Möchtest du zusätzlich zu den Push-Benachrichtigungen eigene Automatisierungen erstellen, kannst du auf `sensor.omada_advisor_status` triggern:

```yaml
alias: "Omada: Kritische Netzwerk-Warnung"
description: "Sendet Benachrichtigung bei Netzwerk-Degradierung"
trigger:
  - platform: state
    entity_id: sensor.omada_advisor_status
condition:
  - condition: template
    value_template: "{{ 'CRITICAL' in states('sensor.omada_advisor_status') }}"
action:
  - service: notify.persistent_notification
    data:
      title: "⚠️ Netzwerk-Störung erkannt"
      message: >-
        {{ state_attr('sensor.omada_advisor_recommendation', 'full_recommendation') }}
```

---

## Fehlerbehebung (Troubleshooting)

### Fehler: "Port 5514 is already in use"
Dieser Fehler tritt auf, wenn auf deinem Home Assistant Host bereits ein anderer Dienst (z. B. ein anderes Syslog-Add-on oder der Omada-Controller) den UDP-Port 5514 belegt.
1. Öffne die Add-on-Seite in Home Assistant.
2. Scrolle zur Karte **Netzwerk**.
3. Ändere den Host-Port für `5514/udp` auf einen freien Port (z. B. **5515**).
4. Trage im Omada Controller unter *Syslog* ebenfalls den neuen Port (z. B. 5515) ein.
5. Starte das Add-on – der Fehler tritt nicht mehr auf.

### Controller-Verbindung schlägt fehl ("Connection Refused" / "Login rejected")
1. Prüfe, ob die IP-Adresse und der Port (Standard: 8043) des Omada Controllers korrekt in den Optionen eingetragen sind.
2. Wenn ein selbstsigniertes SSL-Zertifikat verwendet wird, setze `verify_ssl: false`.
3. Erstelle im Omada Controller einen separaten Viewer- oder Administrator-Benutzer für Home Assistant.

### Keine Syslog-Events im Dashboard
1. Prüfe im Omada Controller unter *Settings -> Log -> Syslog*, ob die IP von Home Assistant und Port **5514** (UDP) eingetragen sind.
2. Stelle sicher, dass der UDP-Port 5514 in deiner Firewall nicht blockiert wird.

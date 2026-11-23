**Software made by ClaudeAI & improved by GrokAI**

# snmp2opcua: SNMP trap to OPC UA gateway

> **Original by Claude** (Anthropic Claude Opus 5.5, November 2026).  
> **Improved by Grok** (xAI, November 2026): packaging (pyproject.toml), MIT license, Dockerfile, cleaner .gitignore, and minor polish. Core logic unchanged from the original `snmp2opcua` repository.
>
> **What it was tested against:**
> - automated tests (98 passed)
> - simulated devices: SNMP v1/v2c/v3 traps and informs, and a simulated GE MDS Orbit master station
> - stand-ins for the OPC UA library (asyncua) and for the desktop window's Tkinter
>
> It has **not yet been run against real devices, a real OPC UA client, or on a real desktop**. Review it and test it with your own equipment before relying on it in production.

Receives SNMP traps from switches, UPSs, PLCs, firewalls and similar devices, and publishes them over OPC UA so SCADA, HMI and historian systems can use them.

```
 devices ──SNMP v1/v2c/v3 trap/inform (UDP 162)──▶ snmp2opcua ──OPC UA──▶ SCADA / HMI / historian
```

It has two modes:

- **server** (default): the gateway runs its own OPC UA server. Each trap updates variables and fires an OPC UA event. Configured devices also get **trap tags in the style of the KEPServerEX SNMP driver**, such as `ns=2;s=Channel1.Switch1.linkDown`.
- **client**: the gateway connects to an OPC UA server you already have and writes trap fields into NodeIds you choose.

## Improvements in this fork (snmp2opcua2)

- Added `pyproject.toml` for modern packaging (`pip install -e .`)
- Added MIT LICENSE
- Added Dockerfile for easy container deployment
- Cleaner `.gitignore`
- Updated README header
- Core SNMP/OPC UA logic is identical to the original repository

## Features

(Full feature list and usage instructions remain the same as the original. See original snmp2opcua for complete details, or check the source files.)

## Install and run

```bash
pip install -e .          # or pip install -r requirements.txt
export SNMP_AUTH_KEY=authpass123 SNMP_PRIV_KEY=privpass123
python -m snmp2opcua -c config.yaml
```

Or with Docker:
```bash
docker build -t snmp2opcua .
docker run --rm -p 1162:1162/udp -p 4840:4840 snmp2opcua
```

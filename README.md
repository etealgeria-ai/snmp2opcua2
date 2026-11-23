**Software made by ClaudeAI and improved by GrokAI**

This repository is a full copy of [snmp2opcua](https://github.com/etealgeria-ai/snmp2opcua) plus packaging improvements. The original SNMP and OPC UA logic is unchanged.

Improvements in this fork:
- `pyproject.toml` so the package installs with `pip install .`
- MIT `LICENSE`
- `Dockerfile` (listens on UDP 1162 by default so it does not need a privileged port)
- Cleaner `.gitignore`

**Software made by ClaudeAI**

# snmp2opcua: SNMP trap to OPC UA gateway

> **Written by Claude.** The code, tests and this README were written by Claude (Anthropic's AI model, Claude Opus 5.5) in November 2026, at the request of the repository owner.
>
> **What it was tested against:**
> - automated tests
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

## Features

- SNMP **v1 traps**, **v2c traps and informs**, and **v3 traps and informs** (informs are acknowledged)
- **SNMPv3 USM**: authentication with MD5, SHA-1 or SHA-224/256/384/512, and encryption with DES, AES-128 or AES-192/256 (both the net-snmp and Cisco key formats). Informs work with engine discovery, and traps get replay protection
- The SNMP decoder is built in and needs no SNMP library. v1 traps are converted to v2 notification OIDs (RFC 3584), so traps from every version look the same downstream
- **Trap tags like KEPServerEX's SNMP driver:**
  - a Channel → Device → Tag tree, with `TRAP_V1:` / `TRAP_V2C:` addresses, the `:Px` port filter and `[n]` table fields
  - a per-device trap events queue (`EVENTS_COUNT`, `EVENTS_001…`) and auto-created coldStart/warmStart/linkUp/linkDown tags
  - KEPServerEX tag CSV import/export
- **Traps from Kepware SNMP Agents**: their `lastTrapDescr` becomes the trap's description, and the agent's system objects get readable names
- **SNMP polling**: reads the RSSI and IP of every GE MDS Orbit remote radio from the master station, plus any OIDs you list, and publishes them as OPC UA tags. A Radios view in the window flags weak and offline remotes
- Community allow-list (v1/v2c), USM users (v3), an "accept packets from all hosts" option with a host list, a setting to accept only some SNMP versions (e.g. v3 only), several network interfaces/ports, and UDP or TCP trap listeners
- Friendly OID names: common MIBs are built in (IF-MIB, SNMPv2-MIB, UPS-MIB, ...), and you can add your own in the config
- OPC UA event severity is mapped per trap name or OID prefix
- Each source device gets its own node with a trap count and its last trap
- A bounded queue holds traps while OPC UA is slow or unreachable. In client mode the gateway reconnects automatically
- **Desktop window** to start and stop the gateway, see live data for every tag, watch traps arrive, see why packets were rejected, run diagnostics, send test traps and edit the configuration
- Runs on Linux and Windows, Python 3.9+ (tested on 3.13)

## Install and run

```bash
pip install -r requirements.txt          # asyncua, PyYAML, cryptography
export SNMP_AUTH_KEY=authpass123 SNMP_PRIV_KEY=privpass123   # v3 keys used by config.yaml (Windows: set ...)
python -m snmp2opcua -c config.yaml      # UDP 162 needs root/admin, see below
```

For a quick test without root, run in one terminal (with the two variables above set):

```bash
python -m snmp2opcua -c config.yaml --port 1162 --log-level DEBUG
```

and in another:

```bash
python -m snmp2opcua.sendtrap --port 1162 --trap-oid linkDown -v ifIndex.3 i 3 -v ifDescr.3 s eth3
python -m snmp2opcua.sendtrap --port 1162 --inform --trap-oid 1.3.6.1.4.1.9999.0.1 -v 1.3.6.1.4.1.9999.1 s "Door open"
python -m snmp2opcua.sendtrap --port 1162 --snmp-version 1 --enterprise 1.3.6.1.4.1.9999 --specific 7
python -m snmp2opcua.sendtrap --port 1162 --snmp-version 3 -u opcgw -a SHA256 -A authpass123 -x AES -X privpass123 --trap-oid linkDown -v ifIndex.3 i 3
python -m snmp2opcua.sendtrap --port 1162 --snmp-version 3 -u opcgw -a SHA256 -A authpass123 -x AES -X privpass123 --inform --trap-oid coldStart
python examples/watch_traps.py opc.tcp://localhost:4840/snmp2opcua/
```

You can also use net-snmp, then browse the server with UaExpert:

```bash
snmptrap -v 2c -c public localhost:1162 '' 1.3.6.1.6.3.1.1.5.3
snmptrap -v 3 -u opcgw -l authPriv -a SHA-256 -A authpass123 -x AES -X privpass123 \
         -e 0x8000000001020304 localhost:1162 '' 1.3.6.1.6.3.1.1.5.3
snmpinform -v 3 -u opcgw -l authPriv -a SHA-256 -A authpass123 -x AES -X privpass123 localhost:1162 '' 1.3.6.1.6.3.1.1.5.1
```

## OPC UA address space (server mode)

All NodeIds are string NodeIds in namespace `urn:snmp2opcua:gateway`, which is usually `ns=2`.

| NodeId | Type | Meaning |
|---|---|---|
| `ns=2;s=Gateway` | Object | Emits a `SnmpTrapEventType` event for every trap |
| `…;s=Gateway.LastTrap.Json` | String | Full last trap as JSON (one atomic snapshot) |
| `…;s=Gateway.LastTrap.SourceIP` / `TrapOID` / `TrapName` / `Version` / `PduType` / `SecurityName` | String | Fields of the last trap (`SecurityName` is the v3 user) |
| `…;s=Gateway.LastTrap.Uptime` | UInt32 | Agent sysUpTime (1/100 s) |
| `…;s=Gateway.LastTrap.ReceivedAt` | DateTime | Receive time (UTC) |
| `…;s=Gateway.LastTrap.VarBindsJson` | String | Varbinds as JSON `[{"oid","name","type","value"}]` |
| `…;s=Gateway.RecentTrapsJson` | String | JSON array of the last N traps, newest first |
| `…;s=Gateway.Devices.<ip>.TrapCount` / `LastTrapOID` / `LastTrapName` / `LastTrapTime` / `LastTrapJson` | | Per-source device |
| `…;s=Gateway.Status.TrapsReceived` / `TrapsPublished` / `TrapsDropped` / `TrapsRejected` / `MalformedPackets` / `StartTime` | | Gateway health |

**Event fields.** `SnmpTrapEventType` is a subtype of BaseEventType. It adds `SourceIP`, `SnmpVersion`, `SecurityName`, `TrapOID`, `TrapName` and `VarBindsJson`. It also fills the standard `Severity`, `Message`, `SourceName` and `Time` fields.

> **Which to use?** For alarms, subscribe to **events**. OPC UA queues them per subscription, so bursts aren't lost. Polling the variables only shows the latest trap. If you read the variables, read `LastTrap.Json`, because the individual `LastTrap.*` fields are written one after another.

## Client mode (write into an existing OPC UA server)

```yaml
opcua:
  mode: client
  client:
    url: opc.tcp://scada-server:4840
    username: gateway
    password: null                  # or env var OPCUA_PASSWORD
    security_string: "Basic256Sha256,SignAndEncrypt,certs/cert.der,certs/key.pem"
    nodes:
      trap_json:   "ns=2;s=SNMP.LastTrapJson"
      trap_name:   "ns=2;s=SNMP.LastTrapName"
      source_ip:   "ns=2;s=SNMP.LastSourceIP"
      severity:    "ns=2;s=SNMP.LastSeverity"
      trap_count:  "ns=2;s=SNMP.TrapCount"
      received_at: "ns=2;s=SNMP.LastTrapTime"
```

The target nodes must already exist and be writable. The gateway reads each node's data type once and converts values to match (String, any integer type, Double/Float, DateTime). The available fields are `trap_json`, `varbinds_json`, `source_ip`, `version`, `security_name`, `trap_oid`, `trap_name`, `uptime`, `received_at`, `severity`, `trap_count` and `summary`.

If the server goes down, traps wait in the queue (`traps.queue_size`) and are written after the gateway reconnects. If a write is rejected (wrong type, no access), the gateway logs it and skips that node.

## Desktop window

```bash
python -m snmp2opcua.gui -c config.yaml           # add --start to start the gateway right away
python -m snmp2opcua --gui -c config.yaml         # same thing
```

On Windows you can also double-click `run_gui.pyw`, which uses the `config.yaml` next to it. The window uses Tkinter, which comes with Python from python.org. On Debian/Ubuntu, install it with `sudo apt install python3-tk`.

- **Toolbar:** *Start gateway* / *Stop gateway*, the config file in use, and the gateway's state. Under it you'll see the UDP address being listened on and the OPC UA endpoint or target server.
- **Counters:** received, published to OPC UA, waiting to publish, rejected, unreadable and dropped. A counter gets an amber or red stripe and a ⚠ label only when something needs attention. Everything else stays grey, following high-performance HMI practice (ISA-101).
- **Traps:** a live list, newest first.
  - High-severity rows (800 or more) are tinted red and medium ones (600–799) amber. The severity number and label are always shown as text as well.
  - You can filter by any text (source, trap name, numeric OID, v3 user, values), pause the feed, and export to CSV.
  - Select a trap to see its full JSON.
- **Live data:** every tag the gateway publishes in one live list, like a quick client.
  - It covers trap tags, the events queue, polled values, Remote1…RemoteN, and the gateway's own OPC UA objects (status counters, last trap, per-source nodes).
  - Columns: tag, value, data type, quality, last update, update count and source (Trap, Poll or Gateway). A value that just changed is highlighted for two seconds, and Bad quality rows are tinted with the word "Bad".
  - Filter by tag name or value, and pick a view: all tags, changed in the last minute, Bad quality, trap tags, polled tags or gateway objects.
  - Click a column heading to sort, *Pause* to freeze the view (updates keep counting), and *Export snapshot CSV…* to save every visible tag with its NodeId.
  - Select a tag to see its OPC UA NodeId (`ns=2;s=…`) and full value. *Copy NodeId* is there for setting up SCADA clients.
- **Tags:** the Channel → Device → Tag tree with live values and Good/Bad quality, like a quick client.
  - By default it shows trap tags, your own tags, `EVENTS_COUNT` and `EVENTS_001`. Tick the box to see every table field and the whole events queue.
  - *Export tags CSV…* writes the selected device's tags in KEPServerEX's CSV layout.
  - *Import tags CSV…* validates a CSV and saves it as the device's `tags_csv` file.
- **Sources:** every address that has sent traps, with a count and its last trap.
- **Radios:** the remote radios of each GE MDS Orbit master: MAC, IP, RSSI, IfIndex, status and last seen, weakest signal first.
  - Remotes below `rssi_warning_dbm` are tinted amber and labelled "weak signal". Offline remotes are tinted red and labelled.
  - An OPC UA tag column shows which `RemoteN` tag each radio has.
  - *Copy as report* gives the same table as the original pysnmp script.
- **Stations:** a form for GE MDS Orbit master stations, so you can change the settings without editing YAML.
  - Fields: channel, name, **IP address**, read community (masked, with *Show*), SNMP version, port, scan rate, timeout, retries, max repetitions, the RSSI warning level, the number and name of the Remote1…RemoteN tags, and whether to receive traps and create the standard trap tags.
  - *Lock current numbers* pins today's Remote numbering in the config.
  - *Add station* and *Remove* manage the list. *Test connection* polls the master with the values on screen and reports how many remotes answered and their RSSI range.
  - *Save* rewrites only the values you changed in `config.yaml`, keeping your comments and layout. It validates first, with the same messages as the manuals (e.g. "Invalid IP address…", "The rate must be within the range of 10 milliseconds and 49 days."), and keeps the previous file as `.bak`. *Save and restart* applies the change straight away.
- **Rejected:** every refused or unreadable packet with the exact reason, e.g. a wrong community, an unknown v3 user, a failed authentication or decryption, or a stale trap.
- **Diagnostics:** health checks that run when you open the tab or press *Run checks*. Each result is marked Problem, Warning, OK or Info, with a "How to fix" note where needed. *Copy report* and *Save report…* produce a plain-text report for a ticket or email, and it never contains keys or passwords. The checks cover:
  - **Configuration:** whether it loads, the SNMP versions accepted, and the v3 users
  - **SNMP listener:** whether the UDP port is free, in use or blocked by permissions; listening on localhost only; this computer's addresses to send traps to; source filtering; the default `public` community
  - **SNMPv3:** the engine ID, boots and time; whether the state file is writable; replay protection; each USM failure counter explained (unknown user, wrong auth key, wrong priv key, wrong security level, stale traps); and which device engines have been seen
  - **OPC UA:** whether `asyncua` is installed; whether the server port is free or answering (server mode) or the target server is reachable, with session state, write errors and the last error (client mode); and the security policy
  - **Gateway:** uptime, queue fill, dropped traps, trap rate and last trap
  - **Environment:** Python, OS, Tk and library versions, and administrator rights
- **Send test trap:** sends v1, v2c or v3 traps and informs to the gateway or any other host. You can pick a configured v3 user or enter custom credentials, which is handy for testing a device's settings.
- **Configuration:** edit `config.yaml`, then use *Check*, *Save* or *Save and restart*. An invalid file is never saved, and the previous version is kept as `config.yaml.bak`.
- **Log:** the gateway's own log messages.

## Devices and trap tags (KEPServerEX SNMP driver style)

The gateway can present traps the way KEPServerEX's SNMP driver does. You configure channels and devices, and each device gets trap tags that SCADA clients read or subscribe to. NodeIds follow Kepware's pattern, `ns=2;s=<Channel>.<Device>.<Tag>`, so screens built against KEPServerEX can usually be pointed at the gateway unchanged.

```yaml
channels:
  - name: Channel1
    devices:
      - name: Switch1
        ip: 192.168.1.20            # traps are matched to the device by source address
        snmp_version: 2c            # 1, 2c or 3 (with a v3: block, one user per device)
        trap: {port: 162, protocol: UDP, community: "", number_of_events: 10, number_of_fields: 10}
        tags:
          - {name: Port3Down, address: "TRAP_V2C:.1.3.6.1.6.3.1.1.5.3:P3"}
          - {name: Port3Down_Name, address: "TRAP_V2C:.1.3.6.1.6.3.1.1.5.3:P3[10]"}
        tags_csv: Switch1_tags.csv  # optional, KEPServerEX tag CSV
```

**Device settings** match the driver's Trap/Inform properties:
- Enable SNMP Trap/Inform Support
- Port (default: the gateway's `listen_port`) and UDP or TCP
- Custom Community (empty accepts any community, or none)
- Number of Events (1–100, default 10) and Number of Fields (1–20, default 10)
- Extended ASCII

A device only takes traps of its own SNMP version. A v3 device only takes traps from its own user, and its user is added to the gateway's SNMPv3 users automatically.

**Tag addresses:**

| Address | Updates on |
|---|---|
| `TRAP_V1:.1.3.6.1.2.1.11:Gx` | SNMPv1 generic trap x: 0 coldStart, 1 warmStart, 2 linkDown, 3 linkUp, 4 authenticationFailure, 5 egpNeighborLoss |
| `TRAP_V1:<enterprise>:G6:Sx` | SNMPv1 enterprise-specific trap x |
| `TRAP_V2C:<trap OID>` | SNMPv2c/v3 trap or inform with that snmpTrapOID |
| `…:Px` | only when the trap's ifIndex varbind is x (the base tag updates too) |
| `…[n]` | table field n: `[1]` arrival time, `[2]` enterprise, `[3]` generic, `[4]` specific, `[5]` sysUpTime, `[6]` varbind count, `[7]`/`[8]` first varbind OID/value, `[9]…` the rest |

How the tags behave:
- A base tag is a Boolean that becomes **1** when its trap arrives. A client writes **0** to reset it.
- Table fields are read-only. If `[n]` points past the end of a message, the tag is shown with Bad quality.
- For SNMPv2c traps, fields 2–4 are derived per RFC 3584.

**Created automatically for every device:**
- `coldStart`, `warmStart`, `linkUp` and `linkDown`, each with `_001`…`_020` table fields. Set `auto_create_tags: false` to skip them.
- The trap events queue:
  - `EVENTS_COUNT`: counts traps; write 0 to reset it.
  - `EVENTS_001`…: newest first; each holds the whole message as a semicolon-separated string.
  - `EVENTS_nnn_FLDCNT` and `EVENTS_nnn_001`…: the field count and the individual fields.

The driver documentation doesn't spell out the field layout of queue messages, so they use the same order as the table fields.

**Tag CSV:** the layout matches KEPServerEX's tag export: Tag Name, Address, Data Type, Client Access, Description and so on. Rows whose address isn't a trap or `EVENTS_` address (polled OIDs, for example) are skipped and reported. Dotted names such as `Traps.Port3Down` become tag groups (folders in OPC UA).

```bash
python -m snmp2opcua.tag_csv check examples/kepware_tags.csv
python -m snmp2opcua.tag_csv export -c config.yaml --device Channel1.Switch1 -o Switch1_tags.csv
```

Traps from addresses that aren't configured devices are still published under `Gateway/LastTrap`, as events and in the window. Diagnostics lists them so you can add devices for them.

## Polling: RSSI from GE MDS Orbit radios

The gateway can poll devices over SNMP as well as receive their traps. The main use is reading signal strength from a **GE MDS Orbit master station** (for example the LN4 module in an Orbit MCR) for every remote radio connected to it.

The master lists its remotes in `MDS-IF-LN-MIB::mIfLnStatusConnRemTable`, entry `1.3.6.1.4.1.4130.10.2.5.1.2.2.1`. The gateway reads three columns:

| Column | MIB object | Syntax |
|---|---|---|
| `.2` | `mIfLnStatusConnRemIpAddress` | InetIpAddress: 4 octets (IPv4) or 16 (IPv6) |
| `.4` | `mIfLnStatusConnRemLinkStatus` | LinkStatus: `associated(4)` means the link is up; `disassociated(5)`, `scanning(1)` and the rest mean it isn't |
| `.6` | `mIfLnStatusConnRemRssi` | Integer32, RSSI in dBm |

The row index is `INDEX { ifIndex, mIfLnStatusConnRemAddress }`. MacAddress has a fixed size, so the index is `<ifIndex>.<6 MAC octets>` with no length in front. A master that sends a length anyway is also understood.

The IP and RSSI columns and the index parsing are the same as the original pysnmp script; link status is an addition. The gateway reads them with its own SNMP code (GETBULK for v2c, GETNEXT for v1), so pysnmp isn't needed. That matters because pysnmp 7 removed the synchronous `nextCmd` the script used.

```yaml
channels:
  - name: Radios
    devices:
      - name: Master_LN4
        ip: 192.168.1.10
        auto_create_tags: false
        polling:
          community: public
          snmp_version: 2c
          scan_rate_ms: 10000
          ge_orbit_remotes: true
          rssi_warning_dbm: -95
        tags:
          - {name: SysName, address: ".1.3.6.1.2.1.1.5.0"}     # any numeric OID is polled with GET
```

**OPC UA tags**, refreshed every scan:

| Tag | Type | Meaning |
|---|---|---|
| `Radios.Master_LN4.Remote1` … `Remote255` | Int32 | RSSI in dBm of the radio with that number, e.g. `ns=2;s=Radios.Master_LN4.Remote7` |
| `….Remote7_IP` / `_MAC` / `_Online` | String / String / Boolean | Which radio Remote7 is, and whether its link is up |
| `Radios.Master_LN4.Remotes.<MAC>.RSSI` | Int32 | The same RSSI, by MAC, e.g. `ns=2;s=Radios.Master_LN4.Remotes.00063D123456.RSSI` |
| `….Remotes.<MAC>.IP` / `.MAC` / `.IfIndex` | String / String / Int32 | The remote's address and row index |
| `….Remotes.<MAC>.LinkStatus` | String | The master's link status for it: `associated`, `disassociated`, `scanning` … |
| `….Remotes.<MAC>.Online` / `.LastSeen` | Boolean / DateTime | Whether its link was up in the last poll, and the last poll where it was |
| `….Remotes.Count` / `.OnlineCount` | UInt32 | Remotes ever seen / online in the last poll |
| `…._Polling.OK` / `.Error` / `.LastPoll` / `.DurationMs` / `.Failures` | | Poll status |

**Remote numbering (Remote1 … Remote255):** SCADA screens can bind to fixed tags, so every radio keeps its number.
- A newly seen remote takes the lowest free number. The numbering is saved in `polling_state_file` (next to the config), so it survives restarts.
- A remote that goes offline keeps its number. So does one that hasn't been seen since a restart.
- To fix numbers for good, pin them under `polling.remote_slots` (number → MAC or IP), or press **Lock current numbers** on the Stations page. Pins take precedence, and their numbers stay reserved until that radio appears.
- Unused numbers have Bad quality. Change the count with `remote_tags` (default 255, up to 1000; 0 turns them off) and the name with `remote_tag_prefix`.
- If there are more remotes than numbers, the Radios view and Diagnostics say which radios have no tag.

How the tags behave:
- A remote's folder is created the first time the master reports it.
- A remote is online while the master lists it with link status `associated`. The master keeps a row for a while after its link drops (`mIfLnStatusConnRemTimeToLive`). In that time the remote shows `Online = 0` and its `LinkStatus` (for example `disassociated`), and its RSSI is the last value the master measured.
- A remote that drops out of the table keeps its last RSSI and gets `Online = 0`.
- If the master doesn't answer for the link status column (older firmware), a listed remote counts as online, and `LinkStatus` has Bad quality.
- If the master stops answering, every polled tag keeps its last value with Bad quality and `_Polling.OK = 0`. The Radios view and Diagnostics then show the error with likely causes (community, the master's SNMP access list, UDP 161).

You can change all of this in the window's **Stations** page instead of editing YAML. The settings are `community`, `port`, `snmp_version` (1 or 2c), `scan_rate_ms` (10 ms to 49 days), `timeout_ms`, `retries`, `max_repetitions` (the gateway halves it automatically if the master answers `tooBig`), `ge_orbit_remotes`, `rssi_warning_dbm`, `remote_tags`, `remote_tag_prefix` and `remote_slots`. Polled values are published in OPC UA server mode. In client mode they appear in the window and Diagnostics only.

**Other values from the same MIB** can be polled as plain OID tags. The master's own LN interface is in `mIfLnStatusTable`, indexed by ifIndex (3 in these examples):

```yaml
        tags:
          - {name: LN_LinkStatus,  address: ".1.3.6.1.4.1.4130.10.2.5.1.2.1.1.1.3",  data_type: Long}   # mIfLnLinkStatus
          - {name: LN_Temperature, address: ".1.3.6.1.4.1.4130.10.2.5.1.2.1.1.9.3",  data_type: Long}   # mIfLnTemperature
          - {name: LN_ActiveNic,   address: ".1.3.6.1.4.1.4130.10.2.5.1.2.1.1.34.3", data_type: Long}   # mIfLnActiveNic
```

TruthValue objects such as `mIfLnActiveNic` and `mIfLnStatusConnRemStatsAlarmed` are `true(1)` / `false(2)`. Poll them as Long. A Boolean tag treats any non-zero value as true, as KEPServerEX does, so `false(2)` would read as true.

**The same report on the command line:**

```bash
python -m snmp2opcua.ge_orbit --ip 192.168.1.10 --community public
REMOTE_MAC         REMOTE_IP        RSSI (dBm)   IF_INDEX
----------------------------------------------------------
00:06:3D:12:34:56  10.10.1.21       -72          3
```

## Traps from Kepware SNMP Agents

KEPServerEX's SNMP Agent Plug-In puts a trap's description into its `lastTrapDescr` system object (`1.3.6.1.4.1.30144.12.<agent>.1.7.0`) and sends it with the trap. The gateway turns that into the trap's **description**. It appears in the JSON, the event message, the window's Description column and the log. The agent's other system objects (sysDescr…sysLocation under `1.3.6.1.4.1.30144.12.<agent>.1.<n>.0`) get readable names, and the agent's sub-identifier is recorded. To get tags for a Kepware trap, copy the V2c OID (or the V1 Enterprise OID and Specific Trap Type) from the trap's properties in KEPServerEX into a `TRAP_V2C:` or `TRAP_V1:…:G6:Sx` address.

## SNMPv3

Add a USM user for each user name your devices send with:

```yaml
snmp:
  versions: [v3]                 # optional: refuse unauthenticated v1/v2c traps
  v3:
    users:
      - name: opcgw
        auth_protocol: SHA256    # MD5, SHA, SHA224, SHA256, SHA384, SHA512, NONE
        auth_key: ${SNMP_AUTH_KEY}
        priv_protocol: AES       # DES, AES, AES192, AES256, AES192C, AES256C, NONE
        priv_key: ${SNMP_PRIV_KEY}
        # engine_ids: [800000090300aabbccddeeff]   # optional: only these devices
```

- **The security level must match.** A user with auth and priv keys only accepts `authPriv` messages, and a user with only an auth key only accepts `authNoPriv`. Anything else is rejected and logged.
- **No per-device engine IDs needed for traps.** With traps the device is the authoritative engine, so the gateway localizes keys to the engine ID inside each message. That means one user entry covers every device that uses those credentials. To lock a user to specific devices, list their engine IDs in `engine_ids`.
- **Informs:** the gateway is the authoritative engine here. Senders discover its engine ID automatically, the same way `snmpinform` and most devices do. The engine ID and a boots counter are kept in `snmp.v3.state_file`, so that file must be writable. You can set a fixed `engine_id` if a device needs it configured by hand.
- **AES-192/256 key formats:** `AES192`/`AES256` use the Blumenthal key extension (net-snmp's `AES-192`/`AES-256`). `AES192C`/`AES256C` use the Reeder extension, which Cisco and many other vendors use (net-snmp's `AES-192-C`/`AES-256-C`). If AES-256 traps fail with "decryption failed", try the other variant.
- **Replay protection** (RFC 3414) rejects stale or replayed traps. A device that resets its engineBoots counter on reboot will be rejected after it reboots. The log tells you when this happens, and you can turn the check off with `replay_protection: false`.
- **Keys** must be at least 8 characters. Use `${ENV_VAR}` so they aren't stored in the file.
- **Troubleshooting:** the log names the cause of each rejection: unknown user, wrong security level, authentication failed (wrong auth key or protocol), decryption failed (wrong priv key or protocol), stale or replayed trap.

## Production notes

- **Port 162**: run as root or Administrator, or on Linux use the included `snmp2opcua.service`, which grants `CAP_NET_BIND_SERVICE`. You can also listen on 1162 and redirect: `iptables -t nat -A PREROUTING -p udp --dport 162 -j REDIRECT --to-ports 1162`.
- **Windows**: stop or disable the built-in **SNMP Trap** service, which holds UDP 162. Open UDP 162 and TCP 4840 in the firewall.
- **If a listener can't start**, the gateway reports it the way the driver does: "Unable to bind trap socket on binding address …, port … and protocol …". Diagnostics checks every configured listener (network interfaces and device trap ports, UDP and TCP) before you start.
- **OPC UA security**: `NoSecurity` is for lab use. For production, set `security_policies: [Basic256Sha256_SignAndEncrypt]` and provide a certificate and key, for example:
  `openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -keyout certs/server_key.pem -outform der -out certs/server_cert.der -subj "/CN=snmp2opcua" -addext "subjectAltName=URI:urn:snmp2opcua:gateway,DNS:$(hostname)"`
- **Community strings and v3 keys** are never published to OPC UA.
- **Linux service:** the included unit reads the v3 keys from `/etc/snmp2opcua.env` and provides `/var/lib/snmp2opcua` for `state_file`.
- Lock down `snmp.allowed_sources` to your device subnets.

## Limitations and extending

- SNMPv3 support covers USM (the user-based security model). It doesn't do VACM access control or filter by context; any configured user that authenticates is accepted.
- There is no MIB compiler. Add vendor names under `traps.oid_names`. Prefix matching means table columns resolve too, e.g. `ifOperStatus.12`.
- To publish somewhere else (MQTT, a database, ...), write a class with `start()`, `publish(trap)`, `update_status(stats)` and `stop()`, and return it from `make_publisher()` in `gateway.py`.

## Tests

```bash
python -m unittest discover -s tests -v
```

The 98 tests cover:

- decoding a hand-encoded v1 packet and every SNMP value type
- INFORM acknowledgements, community filtering and garbled packets
- for SNMPv3: the RFC 3414 key-localization test vectors, a DES known-answer test, and every auth × priv combination
- for SNMPv3: rejection of wrong keys, tampered messages, unknown users and the wrong security level
- for SNMPv3: replay protection, engine discovery, authenticated inform responses, and time-window Reports
- live UDP end-to-end runs with a fake publisher
- the desktop window's controller: start, stop and restart, live trap and rejection events, test traps, config checks with backup, and the port-in-use error
- diagnostics: ports in use, a bad or missing config, an unreachable OPC UA server, a disconnected client session, SNMPv3 failure counters on a running gateway, and that the report contains no secrets
- trap tags:
  - every address form from the driver documentation, plus clear rejections of bad ones
  - device validation messages and auto-created tags
  - port filters, table fields and RFC 3584 identities
  - device version, community and v3-user filtering
  - the events queue and resets, and Extended ASCII
- Kepware agent traps, KEPServerEX tag CSV import/export, the new config checks, and listener error wording
- end-to-end: devices on UDP and on TCP, including a v3 trap split across TCP packets
- polling against a simulated GE Orbit master:
  - GET, GETNEXT and GETBULK walks, with `tooBig` back-off, timeouts and retries
  - the remote-table index and IP parsing, and a report identical to the original script's
  - conformance with MDS-IF-LN-MIB: the table and column OIDs, the fixed-size MAC index (and a length-prefixed one), InetIpAddress as 4 or 16 octets, and link status deciding Online, with a fallback for masters that don't report it
  - remotes going offline, the master going down, value conversion and config checks
  - stable Remote1…RemoteN numbering: persistence across restarts, pins by MAC or IP, overflow, unused numbers
  - an end-to-end gateway run
- the Stations page logic:
  - validation messages
  - edits that change only the edited lines and keep every comment
  - adding, moving, renaming and removing stations
  - the YAML editor's round trips on the real config file

They don't need asyncua.

## Layout

```
snmp2opcua/
  ber.py           BER encode/decode (SNMP subset)
  trap.py          SNMP v1/v2c message → Trap, INFORM ack builder
  snmp_driver.py   KEPServerEX-style devices and trap tags: addresses, events queue, table fields
  tag_csv.py       KEPServerEX tag CSV import/export
  kepware.py       traps from Kepware SNMP Agents (lastTrapDescr, system objects)
  snmp_client.py   SNMP v1/v2c polling client (GET, GETNEXT, GETBULK, walk)
  poller.py        per-device polling: OID tags, GE Orbit remotes, poll status tags
  ge_orbit.py      GE MDS Orbit remote table (RSSI/IP per remote) + command-line report
  stations.py      Stations page logic: list, validate and save GE master stations
  yaml_edit.py     edits config.yaml in place, keeping comments and layout
  snmpv3.py        SNMPv3 messages: auth, timeliness, decrypt, discovery Reports, inform Responses
  usm.py           USM crypto: key localization, HMAC, DES/AES
  receiver.py      UDP and TCP trap listeners, filtering, stats
  oids.py          built-in OID names + resolver
  severity.py      trap → OPC UA severity rules
  opcua_server.py  server mode (asyncua Server)
  opcua_client.py  client mode (asyncua Client)
  gateway.py       wiring, queue, shutdown
  sendtrap.py      test trap/inform sender
  gui.py           desktop window (Tkinter)
  gui_controller.py  runs the gateway in a thread for the window; no Tk code, so it's testable
  diagnostics.py   health checks and the text report for the Diagnostics tab
config.yaml        example configuration
examples/watch_traps.py   OPC UA subscriber for testing
run_gui.pyw        double-click launcher for the desktop window
examples/kepware_tags.csv  example tag CSV in KEPServerEX's layout
```

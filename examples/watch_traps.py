"""Tiny OPC UA client that prints traps published by snmp2opcua (server mode).

  python examples/watch_traps.py opc.tcp://localhost:4840/snmp2opcua/

Subscribes to SnmpTrapEventType events on the Gateway object (no traps missed during
bursts thanks to the event queue) and to LastTrap/Json value changes.
"""
import asyncio
import sys

from asyncua import Client

NAMESPACE = "urn:snmp2opcua:gateway"


class Handler:
    def event_notification(self, event):
        print(f"EVENT  sev={event.Severity:<4} {event.SourceIP:<15} {event.TrapName}  {event.VarBindsJson}")

    def datachange_notification(self, node, val, data):
        print(f"VALUE  LastTrap.Json = {val[:200]}")


async def main(url: str) -> None:
    async with Client(url) as client:
        idx = await client.get_namespace_index(NAMESPACE)
        gateway = client.get_node(f"ns={idx};s=Gateway")
        last_json = client.get_node(f"ns={idx};s=Gateway.LastTrap.Json")
        event_type = await client.nodes.base_event_type.get_child([f"{idx}:SnmpTrapEventType"])

        sub = await client.create_subscription(200, Handler())
        await sub.subscribe_events(gateway, event_type, queuesize=1000)
        await sub.subscribe_data_change(last_json)
        print(f"Watching {url} (Ctrl+C to stop)")
        while True:
            await asyncio.sleep(1)


if __name__ == "__main__":
    try:
        asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "opc.tcp://localhost:4840/snmp2opcua/"))
    except KeyboardInterrupt:
        pass

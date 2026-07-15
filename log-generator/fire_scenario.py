#!/usr/bin/env python3
"""
Fire Bourne scenarios on demand into syslog-ng — for testing/demoing detections
without waiting for the rare ambient SCENARIO_CHANCE roll.

Run inside the generator container:
  docker exec log-generator python3 fire_scenario.py                 # list scenarios
  docker exec log-generator python3 fire_scenario.py db_mass_extract # fire one (partial name ok)
  docker exec log-generator python3 fire_scenario.py phish 5         # fire 5 times
  docker exec log-generator python3 fire_scenario.py all             # fire every scenario once

Each scenario shares host/user/IP across sources so the correlation detections
(B1–B4) light up. See DETECTIONS.md for which scenario triggers which detection.
"""
import os
import sys
import socket
import generate_logs as g

HOST = os.getenv("SYSLOG_HOST", "syslog-ng")
PORT = int(os.getenv("SYSLOG_PORT", "601"))

# friendly name (sc_db_mass_extract -> "db_mass_extract") -> function
SCMAP = {(fn.__name__[3:] if fn.__name__.startswith("sc_") else fn.__name__): fn
         for fn in g.SCENARIOS}


def fire(funcs, count):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    total = 0
    for _ in range(count):
        for fn in funcs:
            title, lines = fn()
            for line in lines:
                if line is not None:  # EDR lines are ingested directly into SDL, nothing to send here
                    s.sendall(line.encode("utf-8"))
            total += len(lines)
            print(f"  fired: {title}  ({len(lines)} events)")
    s.close()
    print(f"\nSent {total} events to {HOST}:{PORT}")


def main():
    args = sys.argv[1:]
    if not args:
        print("Available scenarios:\n")
        for name, fn in SCMAP.items():
            print(f"  {name:20} {fn()[0]}")
        print("\nUsage: fire_scenario.py <name|all> [count]")
        return

    name, count = args[0], (int(args[1]) if len(args) > 1 else 1)
    if name == "all":
        fire(list(SCMAP.values()), count)
        return

    matches = [fn for n, fn in SCMAP.items() if name.lower() in n.lower()]
    if not matches:
        print(f"No scenario matching '{name}'. Run with no args to list them.")
        sys.exit(1)
    fire(matches, count)


if __name__ == "__main__":
    main()

# shelly: how it works

## Architecture, in one sentence

One special agent, configured with a list of Shelly devices, polls each
device directly over HTTP and reports its data as piggyback under that
device's own alias -- so each device becomes its own Checkmk host with
its own services, auto-created by DCD, without ever creating a host by
hand.

## Part 1: the ruleset (`rulesets/shelly.py`)

Two rule specs:

- **`rule_spec_special_agent_shelly`** ("Shelly devices") -- a `List` of
  device entries (alias, IP/host, username, password). This is the
  entire device inventory UI: add a device by clicking "Add device" in
  Setup, no separate config file or script.
- **`rule_spec_shelly_reachability`**, **`rule_spec_shelly_connectivity`**,
  **`rule_spec_shelly_temperature`**, **`rule_spec_shelly_switch`** --
  four `CheckParameters` rules, one per check plugin, each independently
  configurable (or left at its defaults).

## Part 2: `server_side_calls/shelly.py` -- config becomes a command

Once per check cycle, core calls this file's function with whatever
device list was configured in Part 1. It flattens every device into a
repeated `--device/--host/--username/--password` argv group -- one
group per device, all in one command:

```
agent_shelly --device basement --host 192.168.68.170 --username admin --password <secret> \
             --device attic     --host 192.168.68.88  --username admin --password <secret>
```

Nothing is executed here -- it just builds the command line.

## Part 3: `libexec/agent_shelly` -- the actual executable

One line: `exec python3 -m cmk_addons.plugins.shelly.special_agent.agent_shelly "$@"`.
Forwards argv unchanged to Part 4. Exists because core needs an
executable file path to invoke, not a Python function.

## Part 4: `special_agent/agent_shelly.py` -- the real logic

Parses the repeated device groups back into a list, then works in two
separate phases:

**Fetch phase (concurrent, async)** -- for every device, calls three
Shelly HTTP RPC endpoints via `httpx.AsyncClient`: `Shelly.GetDeviceInfo`,
`Shelly.GetStatus` (switches, sys, connectivity, wifi -- everything in
one call, self-revealing however many `switch:N` channels a device
actually has), and `Ble.GetConfig`. All devices are fetched
concurrently via `asyncio.gather`, since Shelly's HTTP transport
doesn't support batching multiple RPC calls into one request (a
JSON-RPC array body just gets a flat `400 Bad Request` -- tested
directly against a real device). Catches `httpx.HTTPError` (the base
class for every error `httpx` raises, including timeouts) per device,
so one unreachable device doesn't take the rest down with it.
Measured ~1.6x-3.2x faster across three runs against 4 real devices,
compared to the earlier sequential `requests`-based version.

**Write phase (sequential, synchronous)** -- once every device's fetch
has completed (or failed), each device's data gets written out one at a
time, wrapped in `ConditionalPiggybackSection(device.alias)` -- the
mechanism that makes the data show up under a *different* hostname
(the device's alias) than the host the special agent actually ran on.
Always writes a `shelly_reachable` marker (`{"alias": ..., "reachable":
true/false}`), even on failure -- this is what lets the Reachability
check track consecutive failures instead of the host just going
silently stale.

These two phases are kept deliberately separate: writing piggyback
sections mutates stdout's "current piggyback target," which would risk
interleaving two devices' output if writes happened while other
devices were still concurrently mid-fetch.

## Part 5: `agent_based/shelly.py` -- four check plugins

All four share the same underlying sections where possible (`shelly_status`
is parsed once, consumed by three different check plugins):

- **Shelly Reachability** -- tracks consecutive failed checks via
  `get_value_store()` (a small persistent store a check keeps across
  runs), comparing against a configurable threshold before going from
  WARN to CRIT.
- **Shelly Info** -- uptime, restart-required, firmware-update-available,
  and temperature (moved here from Switch -- a device's channels share
  one physical sensor, so reporting it per-channel was pure duplication).
- **Shelly Connectivity** -- Bluetooth/MQTT/Cloud, each independently
  configurable as "expect enabled/disabled" or "ignore" (default).
- **Shelly Switch N** -- one service per `switch:N` channel actually
  found in the device's status (1 for a 1PM, 2 for a 2PM, however many
  a device reports -- nothing hardcoded), with configurable power/current
  levels.

## Part 6: `graphing/shelly.py` -- what the numbers look like

Registers proper units/colors for every custom metric, plus a
`Perfometer` per service so the compact Perf-O-Meter column actually
shows something -- a `Metric` definition alone only controls graphing
units/colors, it does **not** make a Perf-O-Meter appear; that needs
its own separate `Perfometer` registration naming the metric(s) to show.
Switch gets power (Watts); Reachability gets its consecutive-failure
count; Connectivity stacks all three of bluetooth/mqtt/cloud into one
bar rather than picking a single representative metric. Metric names
are namespaced `shelly_*` since metric names are global across all of
Checkmk, not scoped per plugin -- bare names like `power`/`current`
risk colliding with existing core checks (UPS/PDU, etc).

## How a device becomes a host, without ever creating one by hand

This is the same mechanism used for auto-creating a host per Docker
container:

1. A DCD connection (Setup > Hosts > Dynamic host management),
   connector type "Piggyback data", source restricted to the special
   agent's own host (the "collector").
2. Whenever the special agent's piggyback output mentions a hostname
   (a device alias) with no matching host yet, DCD creates one --
   `no-agent`/`no-snmp`/piggyback-only, in whatever folder the
   connection specifies.
3. Two host labels get attached automatically via a
   `host_label_function` on the `shelly_reachable` section:
   `shelly/alias:<value>` (unique per device, for targeting one
   specific device in a rule's conditions) and `shelly/device:yes`
   (shared by every device, for targeting all of them at once).

## One gotcha worth remembering

A plain `omd restart <site> apache` does **not** reload the check
engine's plugin registry after an `agent_based/` change -- only a full
`omd restart <site>` does. `packaging/deploy-checkmk-extension.sh`
already does the full restart for this reason.

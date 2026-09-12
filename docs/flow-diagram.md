# shelly: end-to-end flow

```mermaid
flowchart TD
    subgraph Checkmk["Checkmk site"]
        D["rulesets/shelly.py: device list plus 4 check-parameter rules"] -->|params| E["server_side_calls/shelly.py: builds repeated --device argv groups"]
        E -->|core executes| F["libexec/agent_shelly shell shim"]
        F --> G["special_agent/agent_shelly.py: loops devices, queries each over HTTP"]
        G -->|piggyback per device alias| H["agent_based/shelly.py: 4 check plugins"]
        H --> I["Shelly Reachability"]
        H --> J["Shelly Info"]
        H --> K["Shelly Connectivity"]
        H --> L["Shelly Switch N, one per channel"]
        D -.levels and expectations.-> H
        M["graphing/shelly.py: units, colors, Perfometer"] -.renders.-> I
        M -.renders.-> J
        M -.renders.-> K
        M -.renders.-> L
    end

    subgraph DCD["Dynamic host management"]
        N["DCD connection: Piggyback data, source = collector host"] -->|auto-creates| O["one host per device alias"]
        N -->|host_label_function| P["shelly/alias:X and shelly/device:yes labels"]
    end

    G -.piggyback data.-> N
    O --> I
    O --> J
    O --> K
    O --> L

    Q["Shelly device HTTP RPC API"] -.queried by.-> G
```

Reading it top to bottom: `rulesets/shelly.py` is the only thing you
ever touch by hand to add a device or tune a threshold. Everything from
`server_side_calls` through the four check plugins runs automatically
on Checkmk's normal check cycle; the DCD half runs independently,
watching the same piggyback output to keep host objects in sync with
whatever devices are actually configured.

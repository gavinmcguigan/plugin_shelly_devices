# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/special_agent/devices.py
#
# The Device dataclass is shared between agent_shelly.py (CLI parsing,
# orchestration) and each generation's fetch module (gen1.py, gen2.py).
# Defined in its own module so those two can both depend on it without
# a circular import between them.

from dataclasses import dataclass


@dataclass(frozen=True)
class Device:
    alias: str
    generation: str
    host: str
    username: str
    password: str
    timeout: float = 10.0

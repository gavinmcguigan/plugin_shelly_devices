# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/agent_based/gen2_plugins.py
#
# Checkmk's local-extension plugin discovery only scans files directly
# inside agent_based/, not subdirectories -- so the actual Gen2 check
# plugin implementations live organized under agent_based/gen2/, and
# this flat file just re-imports each one so Checkmk's scanner sees
# them. `from x import y` binds `y` into this module's namespace the
# same way defining it here would, so this is otherwise invisible to
# Checkmk's plugin registration.

from cmk_addons.plugins.shelly.agent_based.gen2.connectivity import (
    check_plugin_shelly_connectivity,
)
from cmk_addons.plugins.shelly.agent_based.gen2.info import check_plugin_shelly_info
from cmk_addons.plugins.shelly.agent_based.gen2.input import check_plugin_shelly_input
from cmk_addons.plugins.shelly.agent_based.gen2.inventory_wifi import (
    inventory_plugin_shelly_wifi,
)
from cmk_addons.plugins.shelly.agent_based.gen2.reachable import (
    check_plugin_shelly_reachable,
)
from cmk_addons.plugins.shelly.agent_based.gen2.sections import (
    agent_section_shelly_ble_config,
    agent_section_shelly_device_info,
    agent_section_shelly_input_config,
    agent_section_shelly_reachable,
    agent_section_shelly_status,
    agent_section_shelly_switch_config,
)
from cmk_addons.plugins.shelly.agent_based.gen2.switch import check_plugin_shelly_switch

__all__ = [
    "agent_section_shelly_ble_config",
    "agent_section_shelly_device_info",
    "agent_section_shelly_input_config",
    "agent_section_shelly_reachable",
    "agent_section_shelly_status",
    "agent_section_shelly_switch_config",
    "check_plugin_shelly_connectivity",
    "check_plugin_shelly_info",
    "check_plugin_shelly_input",
    "check_plugin_shelly_reachable",
    "check_plugin_shelly_switch",
    "inventory_plugin_shelly_wifi",
]

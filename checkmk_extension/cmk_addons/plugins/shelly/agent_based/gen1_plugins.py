# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/agent_based/gen1_plugins.py
#
# Checkmk's local-extension plugin discovery only scans files directly
# inside agent_based/, not subdirectories -- so the actual Gen1 check
# plugin implementations live organized under agent_based/gen1/, and
# this flat file just re-imports each one so Checkmk's scanner sees
# them. `from x import y` binds `y` into this module's namespace the
# same way defining it here would, so this is otherwise invisible to
# Checkmk's plugin registration.

from cmk_addons.plugins.shelly.agent_based.gen1.connectivity import (
    check_plugin_shelly_gen1_connectivity,
)
from cmk_addons.plugins.shelly.agent_based.gen1.info import (
    check_plugin_shelly_gen1_info,
)
from cmk_addons.plugins.shelly.agent_based.gen1.inventory_wifi import (
    inventory_plugin_shelly_gen1_wifi,
)
from cmk_addons.plugins.shelly.agent_based.gen1.light import (
    check_plugin_shelly_gen1_light,
)
from cmk_addons.plugins.shelly.agent_based.gen1.reachable import (
    check_plugin_shelly_gen1_reachable,
)
from cmk_addons.plugins.shelly.agent_based.gen1.sections import (
    agent_section_shelly_gen1_identity,
    agent_section_shelly_gen1_reachable,
    agent_section_shelly_gen1_status,
)

__all__ = [
    "agent_section_shelly_gen1_identity",
    "agent_section_shelly_gen1_reachable",
    "agent_section_shelly_gen1_status",
    "check_plugin_shelly_gen1_connectivity",
    "check_plugin_shelly_gen1_info",
    "check_plugin_shelly_gen1_light",
    "check_plugin_shelly_gen1_reachable",
    "inventory_plugin_shelly_gen1_wifi",
]

# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/agent_based/gen2/sections.py
#
# AgentSection registrations for Gen2 devices. Kept in one file since
# several (e.g. shelly_status) are consumed by multiple check plugins,
# rather than belonging to any single one of them.

import json

from cmk.agent_based.v2 import AgentSection, StringTable
from cmk_addons.plugins.shelly.lib import (
    BleConfigSection,
    DeviceInfoSection,
    InputConfigSection,
    ReachableSection,
    StatusSection,
    SwitchConfigSection,
    host_label_function_shelly_reachable,
)


def parse_shelly_status(string_table: StringTable) -> StatusSection:
    return json.loads(string_table[0][0])


agent_section_shelly_status = AgentSection(
    name="shelly_status",
    parse_function=parse_shelly_status,
)


def parse_shelly_device_info(string_table: StringTable) -> DeviceInfoSection:
    return json.loads(string_table[0][0])


agent_section_shelly_device_info = AgentSection(
    name="shelly_device_info",
    parse_function=parse_shelly_device_info,
)


def parse_shelly_ble_config(string_table: StringTable) -> BleConfigSection:
    return json.loads(string_table[0][0])


agent_section_shelly_ble_config = AgentSection(
    name="shelly_ble_config",
    parse_function=parse_shelly_ble_config,
)


def parse_shelly_input_config(string_table: StringTable) -> InputConfigSection:
    return json.loads(string_table[0][0])


agent_section_shelly_input_config = AgentSection(
    name="shelly_input_config",
    parse_function=parse_shelly_input_config,
)


def parse_shelly_switch_config(string_table: StringTable) -> SwitchConfigSection:
    return json.loads(string_table[0][0])


agent_section_shelly_switch_config = AgentSection(
    name="shelly_switch_config",
    parse_function=parse_shelly_switch_config,
)


def parse_shelly_reachable(string_table: StringTable) -> ReachableSection:
    return json.loads(string_table[0][0])


agent_section_shelly_reachable = AgentSection(
    name="shelly_reachable",
    parse_function=parse_shelly_reachable,
    host_label_function=host_label_function_shelly_reachable,
)

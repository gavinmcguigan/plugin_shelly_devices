# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/agent_based/gen1/sections.py
#
# AgentSection registrations for Gen1 devices.

import json

from cmk.agent_based.v2 import AgentSection, StringTable
from cmk_addons.plugins.shelly.gen1_lib import (
    IdentitySection,
    ReachableSection,
    StatusSection,
    host_label_function_shelly_gen1_reachable,
)


def parse_shelly_gen1_status(string_table: StringTable) -> StatusSection:
    return json.loads(string_table[0][0])


agent_section_shelly_gen1_status = AgentSection(
    name="shelly_gen1_status",
    parse_function=parse_shelly_gen1_status,
)


def parse_shelly_gen1_identity(string_table: StringTable) -> IdentitySection:
    return json.loads(string_table[0][0])


agent_section_shelly_gen1_identity = AgentSection(
    name="shelly_gen1_identity",
    parse_function=parse_shelly_gen1_identity,
)


def parse_shelly_gen1_reachable(string_table: StringTable) -> ReachableSection:
    return json.loads(string_table[0][0])


agent_section_shelly_gen1_reachable = AgentSection(
    name="shelly_gen1_reachable",
    parse_function=parse_shelly_gen1_reachable,
    host_label_function=host_label_function_shelly_gen1_reachable,
)

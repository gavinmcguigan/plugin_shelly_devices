# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/gen1_lib.py
#
# Shared types and helpers used across multiple Gen1 check plugins.
# Contains no agent_section_/check_plugin_/inventory_plugin_ objects
# itself -- those must live under agent_based/ to be discovered by
# Checkmk, so this is a plain library module imported by them.
#
# Deliberately independent of gen2_lib.py: Gen1's legacy HTTP API has a
# completely different data shape from Gen2's RPC API, so nothing here
# is shared with Gen2's equivalents.

from typing import Any, Literal, NotRequired, TypedDict

from cmk.agent_based.v2 import HostLabel, HostLabelGenerator, State

StatusSection = dict[str, Any]


class IdentitySection(TypedDict):
    type: str
    mac: str
    auth: bool
    fw: str
    num_outputs: NotRequired[int]
    mode: NotRequired[str]


class ReachableSection(TypedDict):
    alias: str
    reachable: bool


def host_label_function_shelly_gen1_reachable(
    section: ReachableSection,
) -> HostLabelGenerator:
    yield HostLabel("shelly/alias", section["alias"])
    yield HostLabel("shelly/device", "yes")
    yield HostLabel("shelly/generation", "gen1")


Severity = Literal["ignore", "warn", "crit"]

_SEVERITY_STATE: dict[Severity, State] = {
    "ignore": State.OK,
    "warn": State.WARN,
    "crit": State.CRIT,
}

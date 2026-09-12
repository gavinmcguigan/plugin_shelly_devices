# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/agent_based/shelly.py
#
# First check plugin in this extension: device reachability. Info,
# connectivity, and per-switch checks follow in later commits.

import json
from typing import TypedDict

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    HostLabel,
    HostLabelGenerator,
    Result,
    Service,
    State,
    StringTable,
    get_value_store,
)


class ReachableSection(TypedDict):
    alias: str
    reachable: bool


def parse_shelly_reachable(string_table: StringTable) -> ReachableSection:
    return json.loads(string_table[0][0])


def host_label_function_shelly_reachable(section: ReachableSection) -> HostLabelGenerator:
    yield HostLabel("shelly/alias", section["alias"])


agent_section_shelly_reachable = AgentSection(
    name="shelly_reachable",
    parse_function=parse_shelly_reachable,
    host_label_function=host_label_function_shelly_reachable,
)


def discover_shelly_reachable(section: ReachableSection) -> DiscoveryResult:
    yield Service()


class ReachabilityParams(TypedDict):
    failures_before_crit: int


def check_shelly_reachable(params: ReachabilityParams, section: ReachableSection) -> CheckResult:
    value_store = get_value_store()
    consecutive_failures = value_store.get("consecutive_failures", 0)

    if section["reachable"]:
        value_store["consecutive_failures"] = 0
        yield Result(state=State.OK, summary="Reachable")
        return

    consecutive_failures += 1
    value_store["consecutive_failures"] = consecutive_failures

    threshold = params["failures_before_crit"]
    if consecutive_failures >= threshold:
        yield Result(
            state=State.CRIT,
            summary=f"Unreachable for {consecutive_failures} consecutive checks",
        )
    else:
        yield Result(
            state=State.WARN,
            summary=(
                f"Unreachable for {consecutive_failures} consecutive checks "
                f"(CRIT at {threshold})"
            ),
        )


check_plugin_shelly_reachable = CheckPlugin(
    name="shelly_reachable",
    service_name="Shelly Reachability",
    discovery_function=discover_shelly_reachable,
    check_function=check_shelly_reachable,
    check_ruleset_name="shelly_reachability",
    check_default_parameters=ReachabilityParams(failures_before_crit=3),
)

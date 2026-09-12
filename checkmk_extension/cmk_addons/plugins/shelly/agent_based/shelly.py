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
    Result,
    Service,
    State,
    StringTable,
    get_value_store,
)


class ReachableSection(TypedDict):
    reachable: bool


def parse_shelly_reachable(string_table: StringTable) -> ReachableSection:
    return json.loads(string_table[0][0])


agent_section_shelly_reachable = AgentSection(
    name="shelly_reachable",
    parse_function=parse_shelly_reachable,
)


def discover_shelly_reachable(section: ReachableSection) -> DiscoveryResult:
    yield Service()


class Params(TypedDict):
    failures_before_crit: int


def check_shelly_reachable(params: Params, section: ReachableSection) -> CheckResult:
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
    check_default_parameters=Params(failures_before_crit=3),
)

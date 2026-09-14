# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/agent_based/gen2/input.py

from cmk.agent_based.v2 import (
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Metric,
    Result,
    Service,
    State,
)
from cmk_addons.plugins.shelly.gen2_lib import InputConfigSection, StatusSection


def discover_shelly_input(
    section_shelly_status: StatusSection | None,
    section_shelly_input_config: InputConfigSection | None,
) -> DiscoveryResult:
    if section_shelly_status is None:
        return
    for key in section_shelly_status:
        if key.startswith("input:"):
            yield Service(item=key.split(":", 1)[1])


def check_shelly_input(
    item: str,
    section_shelly_status: StatusSection | None,
    section_shelly_input_config: InputConfigSection | None,
) -> CheckResult:
    if section_shelly_status is None:
        return
    input_ = section_shelly_status.get(f"input:{item}")
    if input_ is None:
        return

    input_type = None
    if section_shelly_input_config is not None:
        input_type = section_shelly_input_config.get(f"input:{item}", {}).get("type")
    label = f"Input ({input_type.capitalize()})" if input_type else "Input"

    state = input_.get("state")
    if state is None:
        yield Result(state=State.OK, summary=f"{label}: No state reported")
        return

    yield Result(state=State.OK, summary=f"{label}: {'On' if state else 'Off'}")
    yield Metric("shelly_input_state", 1.0 if state else 0.0)


check_plugin_shelly_input = CheckPlugin(
    name="shelly_input",
    sections=["shelly_status", "shelly_input_config"],
    service_name="Shelly Input %s",
    discovery_function=discover_shelly_input,
    check_function=check_shelly_input,
)

# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/agent_based/gen1/inventory_wifi.py

from cmk.agent_based.v2 import Attributes, InventoryPlugin, InventoryResult, TableRow
from cmk_addons.plugins.shelly.gen1_lib import IdentitySection, StatusSection


def inventorize_shelly_gen1_wifi(
    section_shelly_gen1_status: StatusSection | None,
    section_shelly_gen1_identity: IdentitySection | None,
) -> InventoryResult:
    if section_shelly_gen1_status is None:
        return
    wifi = section_shelly_gen1_status.get("wifi_sta", {})

    if ip_address := wifi.get("ip"):
        yield TableRow(
            path=["networking", "addresses"],
            key_columns={"address": ip_address, "device": "wifi"},
            inventory_columns={"type": "ipv4"},
        )

    wlan_attributes: dict[str, str] = {}
    if ssid := wifi.get("ssid"):
        wlan_attributes["ssid"] = ssid
    if section_shelly_gen1_identity is not None and (
        mac := section_shelly_gen1_identity.get("mac")
    ):
        wlan_attributes["mac_address"] = mac
    if wlan_attributes:
        yield Attributes(
            path=["networking", "wlan"], inventory_attributes=wlan_attributes
        )


inventory_plugin_shelly_gen1_wifi = InventoryPlugin(
    name="shelly_gen1_wifi",
    sections=["shelly_gen1_status", "shelly_gen1_identity"],
    inventory_function=inventorize_shelly_gen1_wifi,
)

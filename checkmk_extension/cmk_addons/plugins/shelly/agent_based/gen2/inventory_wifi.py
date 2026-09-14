# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/agent_based/gen2/inventory_wifi.py

from cmk.agent_based.v2 import Attributes, InventoryPlugin, InventoryResult, TableRow
from cmk_addons.plugins.shelly.lib import DeviceInfoSection, StatusSection


def inventorize_shelly_wifi(
    section_shelly_status: StatusSection | None,
    section_shelly_device_info: DeviceInfoSection | None,
) -> InventoryResult:
    if section_shelly_status is None:
        return
    wifi = section_shelly_status.get("wifi", {})

    if ip_address := wifi.get("sta_ip"):
        yield TableRow(
            path=["networking", "addresses"],
            key_columns={"address": ip_address, "device": "wifi"},
            inventory_columns={"type": "ipv4"},
        )

    wlan_attributes: dict[str, str] = {}
    if ssid := wifi.get("ssid"):
        wlan_attributes["ssid"] = ssid
    if bssid := wifi.get("bssid"):
        wlan_attributes["access_point_mac"] = bssid
    if section_shelly_device_info is not None and (
        mac := section_shelly_device_info.get("mac")
    ):
        wlan_attributes["mac_address"] = mac
    if wlan_attributes:
        yield Attributes(
            path=["networking", "wlan"], inventory_attributes=wlan_attributes
        )


inventory_plugin_shelly_wifi = InventoryPlugin(
    name="shelly_wifi",
    sections=["shelly_status", "shelly_device_info"],
    inventory_function=inventorize_shelly_wifi,
)

# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/server_side_calls/shelly.py
#
# Turns the shelly ruleset's device list into repeated --device/--username/
# --password argv groups for libexec/agent_shelly.

from collections.abc import Iterable, Sequence

from cmk.server_side_calls.v1 import (
    HostConfig,
    Secret,
    SpecialAgentCommand,
    SpecialAgentConfig,
)
from pydantic import BaseModel


class Device(BaseModel, frozen=True):
    alias: str
    host: str
    username: str = ""
    password: Secret | None = None
    timeout: float = 10.0


class Params(BaseModel, frozen=True):
    devices: Sequence[Device]


def _commands_function(
    params: Params,
    _host_config: HostConfig,
) -> Iterable[SpecialAgentCommand]:
    args: list[str | Secret] = []
    for device in params.devices:
        args += [
            "--device",
            device.alias,
            "--host",
            device.host,
            "--username",
            device.username,
            "--password",
            device.password.unsafe() if device.password is not None else "",
            "--timeout",
            str(device.timeout),
        ]
    yield SpecialAgentCommand(command_arguments=args)


special_agent_shelly = SpecialAgentConfig(
    name="shelly",
    parameter_parser=Params.model_validate,
    commands_function=_commands_function,
)

"""
Shared utility: auto-detect the default gateway IP address.
================================================================

Why this exists
-----------------
Earlier phases hardcoded the gateway IP (e.g. 192.168.88.1) directly
into targets.txt and into loadgen.py command lines. This works, but
ties the project to one specific machine/network - moving to another
machine, another network, or the eventual Raspberry Pi deployment
would silently break every script that has a hardcoded IP baked in,
and the failure mode (probing/sending to the wrong host) is not
obviously wrong when it happens.

This module detects the actual default gateway at runtime instead, so
scripts work correctly on whatever network they're run on without
manual editing.

Detection strategy
--------------------
Windows: parses `ipconfig` output for the first non-empty
"Default Gateway" line. This project's development and deployment
target has been Windows throughout, so this is the primary path.

Linux (for the planned Raspberry Pi deployment): parses
`ip route show default`, which reports the default route's gateway
directly in a single, stable-format line - kept here now so the
eventual Linux port does not need this logic rebuilt from scratch.

If detection fails on either platform, callers get a clear
GatewayNotFoundError rather than a silent wrong answer.
"""

import platform
import re
import subprocess


class GatewayNotFoundError(Exception):
    pass


def _get_gateway_windows() -> str:
    try:
        output = subprocess.check_output(["ipconfig"], text=True, errors="ignore")
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        raise GatewayNotFoundError(f"Could not run 'ipconfig': {e}") from e
    return _parse_ipconfig_output(output)


def _get_gateway_linux() -> str:
    try:
        output = subprocess.check_output(["ip", "route", "show", "default"], text=True)
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        raise GatewayNotFoundError(f"Could not run 'ip route show default': {e}") from e
    return _parse_ip_route_output(output)


def get_default_gateway() -> str:
    """Return the machine's current default gateway IPv4 address.

    Raises GatewayNotFoundError if it cannot be determined."""
    system = platform.system()
    if system == "Windows":
        return _get_gateway_windows()
    elif system == "Linux":
        return _get_gateway_linux()
    else:
        raise GatewayNotFoundError(
            f"Gateway auto-detection is not implemented for platform {system!r}. "
            f"Pass the gateway IP explicitly instead."
        )


class InterfaceNotFoundError(Exception):
    pass


def _pick_active_interface(interfaces: list[dict]) -> str:
    """Pure selection logic, given a list of interface dicts in the shape
    Scapy's get_windows_if_list() returns (each with 'name' and 'ips').
    Separated from the Scapy-calling wrapper below so it can be unit
    tested against real captured interface data without needing Scapy
    installed or a real network present.

    Selection rule: the first interface with at least one real IPv4
    address assigned - i.e. not link-local (169.254.x.x, the address
    Windows assigns when nothing else is available), not loopback
    (127.0.0.1), and not an IPv6 address. This is exactly the manual
    rule that was applied by hand throughout this project's setup
    (Phase 1 Section 3.4) to distinguish the genuinely active adapter
    from inactive/virtual ones (Bluetooth PAN, VirtualBox Host-Only,
    Wi-Fi Direct virtual adapters, WAN miniports, loopback) that are
    also present in Windows' interface list."""
    for iface in interfaces:
        for ip in iface.get("ips", []):
            if ":" in ip:  # IPv6 address - skip, we want an IPv4 target
                continue
            if ip.startswith("169.254.") or ip == "127.0.0.1":
                continue
            return iface["name"]
    raise InterfaceNotFoundError(
        "No interface with a real (non link-local, non-loopback) IPv4 address "
        "was found. Is the machine actually connected to a network? Pass "
        "--iface explicitly instead."
    )


def get_active_interface() -> str:
    """Auto-detect the name of the network interface that is actually
    connected and carrying real traffic, so scripts don't need a
    hardcoded --iface value that only works on one specific machine."""
    system = platform.system()
    if system == "Windows":
        try:
            from scapy.arch.windows import get_windows_if_list
        except ImportError as e:
            raise InterfaceNotFoundError(f"Scapy is required for interface auto-detection: {e}") from e
        interfaces = get_windows_if_list()
        return _pick_active_interface(interfaces)
    elif system == "Linux":
        # On Linux, Scapy's own conf.iface already resolves to the
        # interface associated with the default route in almost all
        # cases, so no separate detection logic is needed here.
        from scapy.config import conf
        return conf.iface.name if hasattr(conf.iface, "name") else str(conf.iface)
    else:
        raise InterfaceNotFoundError(
            f"Interface auto-detection is not implemented for platform {system!r}. "
            f"Pass --iface explicitly instead."
        )


# ---------------------------------------------------------------------------
# Parsing logic exposed separately from the subprocess calls, so it can be
# unit-tested against sample command output without needing to actually run
# ipconfig/ip route on the machine running the tests.
# ---------------------------------------------------------------------------

def _parse_ipconfig_output(output: str) -> str:
    for line in output.splitlines():
        if "Default Gateway" in line:
            match = re.search(r":\s*([\d.]+)\s*$", line)
            if match:
                return match.group(1)
    raise GatewayNotFoundError("No 'Default Gateway' line with an IPv4 address found.")


def _parse_ip_route_output(output: str) -> str:
    match = re.search(r"default via ([\d.]+)", output)
    if match:
        return match.group(1)
    raise GatewayNotFoundError("No default route found.")


if __name__ == "__main__":
    try:
        gw = get_default_gateway()
        print(f"Detected default gateway: {gw}")
    except GatewayNotFoundError as e:
        print(f"Error: {e}")
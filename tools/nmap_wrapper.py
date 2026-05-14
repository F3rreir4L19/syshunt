from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Sequence
from typing import Any

from tools.base import ToolOptions, ToolWrapper


class NmapWrapper(ToolWrapper):
    name = "nmap"

    def build_command(self, target: str, options: ToolOptions) -> Sequence[str]:
        return [
            "nmap",
            "--top-ports", "1000",
            "-sV",
            "-oX", "-",
            target,
            *options.extra_args,
        ]

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        """Parse nmap XML output into a list of open-port records."""
        stripped = raw_output.strip()
        if not stripped:
            return []

        try:
            root = ET.fromstring(stripped)
        except ET.ParseError:
            return []

        ports: list[dict[str, Any]] = []
        for host in root.findall("host"):
            addr_el = host.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host.find("address")
            ip = addr_el.get("addr", "") if addr_el is not None else ""

            hostname_el = host.find("hostnames/hostname")
            hostname = hostname_el.get("name", "") if hostname_el is not None else ""

            ports_container = host.find("ports")
            if ports_container is None:
                continue

            for port_el in ports_container.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                service_el = port_el.find("service")
                ports.append({
                    "ip": ip,
                    "hostname": hostname,
                    "port": int(port_el.get("portid", 0)),
                    "protocol": port_el.get("protocol", "tcp"),
                    "service": service_el.get("name", "") if service_el is not None else "",
                    "product": service_el.get("product", "") if service_el is not None else "",
                    "version": service_el.get("version", "") if service_el is not None else "",
                })

        return ports

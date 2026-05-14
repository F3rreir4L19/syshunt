from subprocess import CompletedProcess
from unittest.mock import patch

from tools.base import ToolOptions
from tools.nmap_wrapper import NmapWrapper

_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <hostnames><hostname name="example.com" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache" version="2.4"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


def test_nmap_builds_expected_command() -> None:
    command = NmapWrapper().build_command("example.com", ToolOptions())

    assert command == [
        "nmap", "--top-ports", "1000", "-sV", "-oX", "-", "example.com"
    ]


def test_nmap_builds_command_with_extra_args() -> None:
    command = NmapWrapper().build_command(
        "example.com", ToolOptions(extra_args=["-Pn"])
    )

    assert command[-1] == "-Pn"


def test_nmap_parses_open_ports_only() -> None:
    parsed = NmapWrapper().parse_output(_NMAP_XML)

    assert len(parsed) == 2
    ports = [p["port"] for p in parsed]
    assert 80 in ports
    assert 443 in ports
    assert 22 not in ports


def test_nmap_parses_service_fields() -> None:
    parsed = NmapWrapper().parse_output(_NMAP_XML)

    http_record = next(p for p in parsed if p["port"] == 80)
    assert http_record["ip"] == "93.184.216.34"
    assert http_record["hostname"] == "example.com"
    assert http_record["service"] == "http"
    assert http_record["product"] == "Apache"
    assert http_record["version"] == "2.4"
    assert http_record["protocol"] == "tcp"


def test_nmap_returns_empty_on_invalid_xml() -> None:
    parsed = NmapWrapper().parse_output("not valid xml")

    assert parsed == []


def test_nmap_returns_empty_on_empty_output() -> None:
    assert NmapWrapper().parse_output("") == []


def test_nmap_run_uses_mocked_subprocess() -> None:
    with patch("tools.base.subprocess.run") as run:
        run.return_value = CompletedProcess(
            args=["nmap"], returncode=0, stdout=_NMAP_XML, stderr=""
        )

        result = NmapWrapper().run("example.com")

    assert result.success is True
    assert len(result.parsed_data) == 2
    run.assert_called_once()

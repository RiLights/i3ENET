"""Local diagnostics, automatic fixed reads and profile-bound field coding."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import __version__
from .network import doctor
from .read_workflow import read


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="i3enet", description="BMW i3 ENET reads and selected HU/BDC/VSG01 parameter coding with gateway and compatibility checks.",
        epilog="Coding: i3enet --ecu HU --parm EXBOX/LEGAL_DISCLAIMER_TIME --value 00 --ip MAC_IP. Omit --live to preview.")
    parser.add_argument("--version", action="version", version=f"i3ENET {__version__}")
    from .coding_command import add_arguments
    from .profiles import MODULES
    add_arguments(parser)
    commands = parser.add_subparsers(dest="command")
    local = commands.add_parser("doctor", help="Inspect the Mac's local network interfaces")
    local.add_argument("--json", action="store_true", help="Print the local inspection report")
    for name, help_text in (("read-vin", "Discover the car and verify its VIN"),
                            ("read-block", "Discover, verify VIN/software and read a coding block")):
        command = commands.add_parser(name, help=help_text)
        if name == "read-block":
            command.add_argument('--ecu', choices=MODULES, required=True, help='Module role')
            command.add_argument('--parm', dest='parameter', required=True, help='Verified GROUP/PARAMETER path')
        command.add_argument("--ip", required=True, help="Mac ENET IPv4 address")
        command.add_argument("--live", action="store_true", help="Execute the bounded read sequence; otherwise show its plan")
        command.add_argument("--json", action="store_true", help="Print safe reports, counts and artifact hashes")
    return parser


def _print(report: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    elif report['command'] == 'code':
        from .coding_command import display
        display(report)
    elif report["command"] == "doctor":
        for item in report["interfaces"]:
            print(f"{item['name']}: {item['hardware_port'] or 'unknown port'}; "
                  f"link={item['link_status']}; IPv4={', '.join(item['ipv4']) or 'none'}")
        print(f"Local inspection: {report['local_inspection_status']}")
        if report["issues"]:
            print("Issues: " + ", ".join(report["issues"]))
    elif report["outcome"] == "plan_only":
        print(f"Mac IP: {report['source_address']}")
        print("Plan: " + " → ".join(report["planned_steps"]))
        print(f"Maximum: 1 discovery packet, {report['maximum_application_frames']} diagnostic reads, "
              f"{report['maximum_application_bytes']} application bytes. Add --live to read.")
    elif report["outcome"] in ("vin_read", "block_read"):
        print(f"Car gateway: {report['gateway_address']}; VIN: {report['masked_vin']}")
        if report["outcome"] == "block_read":
            print(f"{report['ecu']} / {report['block_name']}: {report['value_byte_count']} bytes")
            print(f"{report['parameter']}: {report['parameter_value_hex']}")
            print(f"Meaning: {report['parameter_meaning']} ({report['meaning_evidence_status']})")
        print(f"Saved originals: {report['raw_artifacts']['directory']}")
    else:
        print(f"Read stopped at {report['failed_step']}: {report['reason']}")
        print(f"Confirmed application bytes sent: {report['vehicle_bytes_confirmed_sent']}")


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    parser = _parser()
    args = parser.parse_args(arguments)
    if args.command is None:
        missing = [flag for flag, value in (('--ecu', args.ecu), ('--parm', args.parameter),
                   ('--value', args.value), ('--ip', args.ip)) if value is None]
        if missing:
            parser.error('coding requires ' + ', '.join(missing))
        from .coding_command import run
        report = run(args)
    else:
        if args.value is not None or args.expect is not None or args.keys is not None:
            parser.error('--value, --expect and --keys are coding options')
        if args.command != 'read-block' and (args.ecu is not None or args.parameter is not None):
            parser.error('--ecu and --parm require coding or read-block')
        if args.command == 'doctor' and (args.ip is not None or args.live):
            parser.error('doctor performs local inspection only')
        report = doctor() if args.command == "doctor" else read(args.command, args.ip, live=args.live,
            ecu=args.ecu, parameter=args.parameter)
    _print(report, args.json)
    if args.command == "doctor":
        return 0 if report["local_inspection_status"] == "complete" else 1
    if args.command is None:
        return 0 if report['outcome'] in ('plan_only', 'already_set') or report.get('transaction_complete') is True else 1
    return 0 if report["outcome"] in ("plan_only", "vin_read", "block_read") else 1

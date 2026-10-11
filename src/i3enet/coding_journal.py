"""Durable private transaction originals; storage never grants send authority.

Only explicit engine callbacks record traffic. Raw requests precede attempts;
raw receipts precede clocks/parsing. Sealing independently reopens the originals.
Keys are never stored. Tests use synthetic bytes only.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
from pathlib import Path

from .artifacts import ArtifactError, DiscoveryArtifactStore
from .coding_preparation import GROUP_LENGTHS, CodingSnapshot, PreparedCoding, verify_coding_readback, CodingEdit
from .coding_contract import contract, transaction_stages, transaction_bounds
from .coding_protocol import (
    CodingProtocolError, cps_read_request, cps_write_request, group_read_request,
    group_write_request, negative_response, parse_cps_read_response,
    parse_cps_write_response, parse_group_read_response, parse_group_write_response,
    parse_key_response, parse_ping_response, parse_reset_response,
    parse_seed_response, parse_session_response, parse_signature_check_response,
    ping_request, reset_request, seed_request, session_request, signature_check_request,
)
from .coding_signature import RSA1024PublicKey, verify_coding1, verify_security_access
from .evidence import _invalid_constant, _open_directory, _read_private_file, _unique_object
from .hsfz import Control, HSFZError, IncrementalParser, expected_ack_echo
from .network import GatewayNetwork
from .svk import _software_tuple, parse_svk_value
from .uds import NegativeResponse, ReadDataByIdentifierRequest, parse_read_data_response

SCHEMA = "i3enet-coding-journal/1"
CODE_STAGES, POST_STAGES = transaction_stages('HU')
STAGES = CODE_STAGES + POST_STAGES
MAX_EVENTS = 1024
MAX_EVENT_BYTES = 524288
MAX_RECEIPTS = 256
MAX_RECEIVED_BYTES = 131072
_PIN_NAMES = {"discovery", "identity", "svk", "session", "seed", "signing_configuration", "snapshot", "cps"}


class JournalError(ArtifactError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _need(ok: bool, reason: str) -> None:
    if not ok:
        raise JournalError(reason)


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _time(value: object, *, optional: bool = False) -> bool:
    return (optional and value is None) or (type(value) in (int, float)
            and 0 <= value <= 1e12 and math.isfinite(value))


def _frame(uds: bytes, *, target: int = 0x63) -> bytes:
    return (len(uds) + 2).to_bytes(4, "big") + b"\x00\x01\xf4" + bytes((target,)) + uds


def _limits(module):
    if module == 'HU': return MAX_EVENTS, MAX_EVENT_BYTES, MAX_RECEIPTS, 128
    cap = transaction_bounds(module)[2]
    return 4096, 2097152, 2 * cap, cap


def _request_shape(stage: str, request: bytes, module='HU') -> bool:
    spec = contract(module)
    def frame(uds, *, target=None): return _frame(uds, target=spec.target if target is None else target)
    if type(request) is not bytes:
        return False
    if stage in ("current_svk", "post_svk"):
        return request == frame(b"\x22\xf1\x01")
    if stage in ("current_vin", "post_vin"):
        return request == frame(b"\x22\xf1\x90", target=0x10)
    if stage == "post_ping":
        return request == frame(ping_request(layout="f186_state"))
    for prefix in ("original_", "readback_"):
        if stage.startswith(prefix):
            return request == frame(group_read_request(int(stage[len(prefix):], 16), module=module))
    fixed = {"extended_session": session_request(3), "coding_session": session_request(0x41),
             "security_seed": seed_request(), "check_signature": signature_check_request(),
             "read_cps": cps_read_request(), "post_cps": cps_read_request(), "reset": reset_request(),
             "current_cps": cps_read_request(), "default_session": session_request(1)}
    if stage in fixed:
        return request == frame(fixed[stage])
    if stage == "security_key":
        return len(request) == 142 and request[:14] == frame(b'\x27\x02' + bytes.fromhex('00000020') + bytes(128))[:14]
    if stage == "write_cps":
        return len(request) == 18 and request[:11] == frame(cps_write_request(b"\0" * 7))[:11]
    if stage.startswith("write_"):
        address = int(stage[6:], 16)
        length = dict(spec.groups)[address]
        return len(request) == length + 11 and request[:11] == frame(group_write_request(address, b"\0" * length, module=module))[:11]
    return False


class CodingJournal(DiscoveryArtifactStore):
    """Unique immutable originals plus a bounded, fsynced hash-chain journal."""
    _category = "coding-transaction"

    def __init__(self, project_directory: Path, *, binding: tuple,
                 source_pins: dict[str, str], evidence_status: str, edit: CodingEdit | None = None):
        _need(type(binding) is tuple and len(binding) in (4, 6), "journal_binding_shape")
        network = GatewayNetwork(binding[0], binding[1], binding[2], binding[3],
                                 binding[4] if len(binding) == 6 else "255.255.0.0",
                                 binding[5] if len(binding) == 6 else "Reviewed Ethernet")
        _need(type(source_pins) is dict and {"discovery", "identity", "svk"} <= source_pins.keys()
              and source_pins.keys() <= _PIN_NAMES
              and all(type(p) is str and re.fullmatch("[0-9a-f]{64}", p) for p in source_pins.values()),
              "journal_source_pins")
        _need(evidence_status in ("SYNTHETIC_FIXTURE", "LOCAL_OBSERVATION"), "journal_evidence_status")
        self._context = {"schema": SCHEMA, "binding": list(binding), "source_pins": dict(source_pins),
                         "evidence_status": evidence_status, "storage_is_send_authority": False}
        if edit is not None:
            _need(type(edit) is CodingEdit, 'journal_edit_invalid')
            edit.__post_init__()
            self._context['selected_edit'] = edit.summary()
        self._module = 'HU' if edit is None else edit.module
        self._code_stages, post = transaction_stages(self._module)
        self._stages = self._code_stages + post
        self._max_events, self._max_event_bytes, self._max_receipts, self._chunk_cap = _limits(self._module)
        if self._module != 'HU': self._context['module'] = self._module
        self._events_fd = None
        self._events: list[dict] = []
        self._chain = "0" * 64
        self._event_bytes = 0
        self._intents: list[dict] = []
        self._receipts: list[dict] = []
        self._connections: dict[int, dict] = {}
        self._sealed = False
        super().__init__(project_directory)
        try:
            self._write("context.json", _json(self._context) + b"\n")
            self._events_fd = os.open("events.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                      0o600, dir_fd=self._directory_fd)
            os.fchmod(self._events_fd, 0o600)
            self._append("created", {})
        except (OSError, KeyboardInterrupt):
            self.close()
            raise JournalError("journal_prepare_failed") from None

    def __repr__(self) -> str:
        return f"CodingJournal(requests={len(self._intents)}, receipts={len(self._receipts)}, originals=<private>)"

    def _write(self, name: str, data: bytes) -> None:
        _need(self._directory_fd is not None, "journal_closed")
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self._directory_fd)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
        finally:
            os.close(fd)
        os.fsync(self._directory_fd)

    def _append(self, event: str, data: dict) -> None:
        _need(not self._sealed and self._events_fd is not None, "journal_terminal")
        item = {"sequence": len(self._events), "previous_sha256": self._chain,
                "event": event, "data": data}
        digest = _hash(_json(item))
        raw = _json(dict(item, sha256=digest)) + b"\n"
        _need(len(self._events) < self._max_events and self._event_bytes + len(raw) <= self._max_event_bytes,
              "journal_event_limit")
        offset = 0
        while offset < len(raw):
            written = os.write(self._events_fd, raw[offset:])
            if written <= 0:
                raise JournalError("journal_short_write")
            offset += written
        os.fsync(self._events_fd); os.fsync(self._directory_fd)
        self._events.append(dict(item, sha256=digest))
        self._chain = digest; self._event_bytes += len(raw)

    def connection_attempted(self, connection_index: int, at: float) -> None:
        _need(type(connection_index) is int and connection_index in (1, 2)
              and connection_index not in self._connections and _time(at), "journal_connection_order")
        if connection_index == 2:
            _need(self._connections.get(1, {}).get("closed") is True
                  and len(self._intents) == len(self._code_stages), "journal_reconnection_order")
        self._append("connection_attempted", {"connection": connection_index, "at": at})
        self._connections[connection_index] = {"attempted": True, "opened": False, "closed": False}

    def opened(self, connection_index: int, at: float) -> None:
        state = self._connections.get(connection_index, {})
        _need(state.get("attempted") and not state.get("opened") and not state.get("closed") and _time(at),
              "journal_open_order")
        self._append("opened", {"connection": connection_index, "at": at})
        state["opened"] = True

    def before_attempt(self, stage: str, request: bytes, *, connection_index: int, at: float) -> int:
        _need(not self._sealed and self._events_fd is not None, "journal_terminal")
        index = len(self._intents)
        _need(index < len(self._stages) and stage == self._stages[index] and _request_shape(stage, request, self._module),
              "journal_request_order_or_shape")
        expected_connection = 1 if index < len(self._code_stages) else 2
        state = self._connections.get(connection_index, {})
        _need(type(connection_index) is int and connection_index == expected_connection
              and state.get("opened") and not state.get("closed") and _time(at), "journal_request_connection")
        _need(not self._intents or self._intents[-1].get("outcome") == "positive", "journal_previous_not_positive")
        token = index + 1; name = f"request-{token:03d}.bin"
        self._write(name, request)
        row = {"token": token, "stage": stage, "connection": connection_index, "at": at,
               "file": name, "byte_length": len(request), "sha256": _hash(request)}
        self._append("request_intent", row)
        self._intents.append(dict(row))
        return token

    def after_attempt(self, token: int, accepted_bytes: int | None, uncertain: bool, at: float | None) -> None:
        _need(type(token) is int and 1 <= token <= len(self._intents), "journal_token")
        row = self._intents[token - 1]
        _need("accepted_bytes" not in row and type(uncertain) is bool and _time(at, optional=True)
              and (accepted_bytes is None or (type(accepted_bytes) is int and 0 <= accepted_bytes <= row["byte_length"]))
              and (accepted_bytes is not None or uncertain), "journal_send_accounting")
        self._append("send_result", {"token": token, "accepted_bytes": accepted_bytes, "uncertain": uncertain, "at": at})
        row.update(accepted_bytes=accepted_bytes, uncertain=uncertain, send_at=at)

    def after_attempt_at(self, token: int, at: float) -> None:
        _need(type(token) is int and 1 <= token <= len(self._intents) and _time(at), "journal_send_time")
        row = self._intents[token - 1]
        _need("accepted_bytes" in row and row.get("send_at") is None, "journal_send_time_order")
        self._append("send_time", {"token": token, "at": at}); row["send_at"] = at

    def received(self, token: int, raw: bytes, at: float | None = None) -> int:
        _need(not self._sealed and self._events_fd is not None, "journal_terminal")
        _need(type(token) is int and token == len(self._intents) and token > 0
              and "accepted_bytes" in self._intents[token - 1] and "outcome" not in self._intents[token - 1],
              "journal_receive_order")
        _need(type(raw) is bytes and 0 < len(raw) <= 4096 and _time(at, optional=True)
              and len(self._receipts) < self._max_receipts
              and sum(r["byte_length"] for r in self._receipts) + len(raw) <= MAX_RECEIVED_BYTES,
              "journal_receive_limit")
        receipt = len(self._receipts) + 1; name = f"recv-{receipt:03d}.bin"
        self._write(name, raw)
        row = {"receipt": receipt, "token": token, "at": at, "file": name,
               "byte_length": len(raw), "sha256": _hash(raw)}
        self._append("received", row); self._receipts.append(dict(row))
        return receipt

    def received_at(self, receipt: int, at: float) -> None:
        _need(type(receipt) is int and receipt == len(self._receipts) and receipt > 0 and _time(at), "journal_receive_time")
        row = self._receipts[receipt - 1]
        _need(row["at"] is None, "journal_receive_time_order")
        self._append("receive_time", {"receipt": receipt, "at": at}); row["at"] = at

    def completed(self, token: int, outcome: str, nrc: int | None, pending_count: int) -> None:
        _need(type(token) is int and token == len(self._intents) and token > 0, "journal_completion_token")
        row = self._intents[token - 1]
        _need("outcome" not in row and type(outcome) is str and re.fullmatch("[a-z_]{1,64}", outcome)
              and (nrc is None or (type(nrc) is int and 0 <= nrc <= 255))
              and type(pending_count) is int and 0 <= pending_count <= 4, "journal_completion_shape")
        self._append("completed", {"token": token, "outcome": outcome, "nrc": nrc, "pending_count": pending_count})
        row.update(outcome=outcome, nrc=nrc, pending_count=pending_count)

    def closed(self, connection_index: int, uncertain: bool, at: float | None) -> None:
        state = self._connections.get(connection_index, {})
        _need(type(connection_index) is int and state.get("attempted") and not state.get("closed")
              and type(uncertain) is bool and _time(at, optional=True), "journal_close_order")
        self._append("closed", {"connection": connection_index, "uncertain": uncertain, "at": at})
        state["closed"] = True

    def finish(self, *, prepared: PreparedCoding | None, as_public_key: RSA1024PublicKey | None,
               expected_vin: str, expected_svk: bytes, expected_cps: bytes, profile: object,
               result_report: dict[str, object]) -> dict[str, object]:
        _need(not self._sealed, "journal_terminal")
        facts = validate_journal(self.directory, expected_context=self._context, prepared=prepared,
                                 as_public_key=as_public_key, expected_vin=expected_vin,
                                 expected_svk=expected_svk, expected_cps=expected_cps, profile=profile)
        for key in ("vehicle_bytes_confirmed_sent", "application_frames_attempted", "application_frames_sent"):
            if key in result_report:
                _need(type(result_report[key]) is int and result_report[key] >= 0, "journal_report_accounting")
                if key == "application_frames_attempted":
                    _need(facts["recorded_attempt_results"] <= result_report[key] <= facts["request_intents"],
                          "journal_report_accounting")
                    continue
                expected = {"vehicle_bytes_confirmed_sent": facts["confirmed_application_bytes"],
                            "application_frames_attempted": facts["request_intents"],
                            "application_frames_sent": facts["full_requests_confirmed"]}[key]
                _need(result_report[key] == expected, "journal_report_accounting")
        raw_events = _read_owned(self.directory, "events.jsonl", self._max_event_bytes)
        manifest = {"schema": SCHEMA, "context_sha256": _hash(_json(self._context) + b"\n"),
                    "events_sha256": _hash(raw_events), "event_count": len(self._events),
                    "last_event_sha256": self._chain, "facts": facts,
                    "no_replay_or_resume": True, "keys_retained": False}
        encoded = _json(manifest) + b"\n"; self._write("manifest.json", encoded); self._sealed = True
        return {"directory": str(self.directory), "manifest_sha256": _hash(encoded), **facts}

    def close(self) -> None:
        if self._events_fd is not None:
            fd, self._events_fd = self._events_fd, None
            try:
                os.close(fd)
            finally:
                super().close()
        else:
            super().close()


def _read_owned(directory: Path, name: str, maximum: int) -> bytes:
    fd = _open_directory(directory)
    try:
        return _read_private_file(fd, name, maximum)
    finally:
        os.close(fd)


def _reopen(directory: Path, expected_context: dict, manifest_sha256: str | None) -> tuple:
    fd = _open_directory(directory)
    try:
        context_raw = _read_private_file(fd, "context.json", 16384)
        context = json.loads(context_raw, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
        _need(_json(context) == _json(expected_context), "journal_context_mismatch")
        module = context.get("module", "HU"); spec = contract(module)
        coding, post = transaction_stages(module); stages = coding + post
        event_cap, event_bytes, receipt_cap, chunk_cap = _limits(module)
        raw = _read_private_file(fd, "events.jsonl", event_bytes)
        _need(raw.endswith(b"\n"), "journal_truncated_event")
        events = [json.loads(line, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
                  for line in raw.splitlines()]
        _need(0 < len(events) <= event_cap and events[0].get("event") == "created", "journal_event_limit")
        previous = "0" * 64; requests = []; receipts = []; connections = {}
        expected_files = {"context.json", "events.jsonl", "manifest.json"}
        for index, event in enumerate(events):
            _need(type(event) is dict and set(event) == {"sequence", "previous_sha256", "event", "data", "sha256"}
                  and type(event["sequence"]) is int and event["sequence"] == index
                  and event["previous_sha256"] == previous and type(event["data"]) is dict,
                  "journal_event_shape")
            previous = event["sha256"]
            _need(previous == _hash(_json({k: event[k] for k in event if k != "sha256"})), "journal_hash_chain")
            kind, data = event["event"], event["data"]
            if kind == "created":
                _need(index == 0 and not data, "journal_created_event")
            elif kind == "request_intent":
                token = len(requests) + 1
                _need(set(data) == {"token", "stage", "connection", "at", "file", "byte_length", "sha256"}
                      and token <= len(stages) and type(data["token"]) is int and data["token"] == token
                      and data["stage"] == stages[token - 1] and data["file"] == f"request-{token:03d}.bin"
                      and type(data["byte_length"]) is int and _time(data["at"]), "journal_original_request_order")
                connection = 1 if token <= len(coding) else 2
                state = connections.get(connection, {})
                _need(type(data["connection"]) is int and data["connection"] == connection
                      and "opened" in state and "closed" not in state
                      and (not requests or requests[-1].get("outcome") == "positive"), "journal_original_request_connection")
                value = _read_private_file(fd, data["file"], max(n for _, n in spec.groups) + 11)
                _need(len(value) == data["byte_length"] and _hash(value) == data["sha256"]
                      and _request_shape(data["stage"], value, module), "journal_original_request_hash_or_shape")
                expected_files.add(data["file"]); requests.append(dict(data, raw=value))
            elif kind in ("send_result", "send_time", "completed"):
                _need(type(data["token"]) is int and data["token"] == len(requests) and requests,
                      "journal_original_result_order")
                row = requests[data["token"] - 1]
                if kind == "send_result":
                    count = data["accepted_bytes"]
                    _need(set(data) == {"token", "accepted_bytes", "uncertain", "at"}
                          and "accepted_bytes" not in row and type(data["uncertain"]) is bool
                          and _time(data["at"], optional=True)
                          and (count is None or (type(count) is int and 0 <= count <= row["byte_length"]))
                          and (count is not None or data["uncertain"]), "journal_duplicate_send_result")
                    row.update(accepted_bytes=data["accepted_bytes"], uncertain=data["uncertain"], send_at=data["at"])
                elif kind == "send_time":
                    _need(set(data) == {"token", "at"} and _time(data["at"])
                          and "accepted_bytes" in row and row["send_at"] is None, "journal_duplicate_send_time")
                    row["send_at"] = data["at"]
                else:
                    _need(set(data) == {"token", "outcome", "nrc", "pending_count"}
                          and "outcome" not in row and type(data["outcome"]) is str
                          and re.fullmatch("[a-z_]{1,64}", data["outcome"])
                          and (data["nrc"] is None or (type(data["nrc"]) is int and 0 <= data["nrc"] <= 255))
                          and type(data["pending_count"]) is int and 0 <= data["pending_count"] <= 4,
                          "journal_duplicate_completion")
                    row.update(outcome=data["outcome"], nrc=data["nrc"], pending_count=data["pending_count"])
            elif kind == "received":
                receipt = len(receipts) + 1
                _need(set(data) == {"receipt", "token", "at", "file", "byte_length", "sha256"}
                      and type(data["receipt"]) is int and data["receipt"] == receipt
                      and type(data["token"]) is int and data["token"] == len(requests) and requests
                      and "accepted_bytes" in requests[-1] and "outcome" not in requests[-1]
                      and _time(data["at"], optional=True) and type(data["byte_length"]) is int
                      and data["file"] == f"recv-{receipt:03d}.bin", "journal_original_receive_order")
                value = _read_private_file(fd, data["file"], 4096)
                _need(len(value) == data["byte_length"] and _hash(value) == data["sha256"], "journal_original_receive_hash")
                expected_files.add(data["file"]); receipts.append(dict(data, raw=value))
            elif kind == "receive_time":
                _need(set(data) == {"receipt", "at"} and type(data["receipt"]) is int
                      and data["receipt"] == len(receipts) and receipts and receipts[-1]["at"] is None
                      and _time(data["at"]),
                      "journal_original_receive_time_order")
                receipts[-1]["at"] = data["at"]
            elif kind in ("connection_attempted", "opened", "closed"):
                connection = data["connection"]
                expected_keys = {"connection", "at", "uncertain"} if kind == "closed" else {"connection", "at"}
                _need(set(data) == expected_keys and type(connection) is int and connection in (1, 2)
                      and _time(data["at"], optional=kind == "closed")
                      and (kind != "closed" or type(data["uncertain"]) is bool), "journal_original_connection")
                state = connections.setdefault(connection, {})
                _need(kind not in state, "journal_duplicate_connection_event")
                if kind == "connection_attempted":
                    _need(not state and (connection == 1 or ("closed" in connections.get(1, {})
                          and len(requests) == len(coding) and requests[-1].get("outcome") == "positive")),
                          "journal_original_reconnect_order")
                elif kind == "opened":
                    _need("connection_attempted" in state and "closed" not in state, "journal_original_open_order")
                else:
                    _need("connection_attempted" in state, "journal_original_close_order")
                state[kind] = data
            else:
                raise JournalError("journal_unknown_event")
        _need(len(receipts) <= receipt_cap and sum(row["byte_length"] for row in receipts) <= MAX_RECEIVED_BYTES,
              "journal_receive_limit")
        for connection in (1, 2):
            connection_tokens = {row["token"] for row in requests if row["connection"] == connection}
            values = [row for row in receipts if row["token"] in connection_tokens]
            _need(len(values) <= chunk_cap and sum(row["byte_length"] for row in values) <= 65536,
                  "journal_connection_receive_limit")
        files = set(os.listdir(fd))
        _need(files <= expected_files, "journal_unexpected_file")
        seal = None
        if "manifest.json" in files:
            _need(type(manifest_sha256) is str and re.fullmatch("[0-9a-f]{64}", manifest_sha256),
                  "journal_manifest_pin_required")
            encoded = _read_private_file(fd, "manifest.json", 16384)
            _need(_hash(encoded) == manifest_sha256, "journal_manifest_pin_mismatch")
            seal = json.loads(encoded, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
            _need(type(seal) is dict and set(seal) == {"schema", "context_sha256", "events_sha256", "event_count",
                  "last_event_sha256", "facts", "no_replay_or_resume", "keys_retained"}
                  and seal["schema"] == SCHEMA and seal["context_sha256"] == _hash(context_raw)
                  and seal["events_sha256"] == _hash(raw) and type(seal["event_count"]) is int
                  and seal["event_count"] == len(events) and seal["last_event_sha256"] == previous
                  and seal["no_replay_or_resume"] is True and seal["keys_retained"] is False,
                  "journal_seal_mismatch")
        else:
            _need(manifest_sha256 is None, "journal_missing_manifest")
        return context, requests, receipts, connections, seal
    except JournalError:
        raise
    except (OSError, ValueError, KeyError, IndexError, TypeError, AttributeError, RecursionError):
        raise JournalError("journal_original_structure_invalid") from None
    finally:
        os.close(fd)


def _positive(stage: str, pdu: bytes, request: bytes, prepared: PreparedCoding,
              as_public_key: RSA1024PublicKey, expected_vin: str, expected_svk: bytes,
              expected_cps: bytes, profile: object, private: dict) -> None:
    module = prepared.edit.module
    def frame(pdu): return _frame(pdu, target=contract(module).target)
    if stage in ("current_vin", "current_svk", "post_svk", "post_vin"):
        did = 0xF190 if stage in ("current_vin", "post_vin") else 0xF101
        response = parse_read_data_response(pdu, ReadDataByIdentifierRequest(did))
        expected = expected_vin.encode("ascii") if did == 0xF190 else expected_svk
        _need(not isinstance(response, NegativeResponse) and response.value == expected, "journal_identity_value_mismatch")
        if did != 0xF190:
            _software_tuple(parse_svk_value(response.value), module=module)
    elif stage.startswith(("original_", "readback_")):
        prefix = "original_" if stage.startswith("original_") else "readback_"
        address = int(stage[len(prefix):], 16)
        value = parse_group_read_response(pdu, address, module=module)
        snapshot = prepared.original if prefix == "original_" else prepared.candidate
        _need(value == dict(snapshot.groups)[address], "journal_group_value_mismatch")
        if prefix == "readback_":
            private.setdefault("readback", []).append((address, value))
    elif stage in ("extended_session", "coding_session"):
        parse_session_response(pdu, 3 if stage == "extended_session" else 0x41, layout=profile.session_layout)
    elif stage == "security_seed":
        seed = parse_seed_response(pdu).seed
        _need(len(seed) == profile.seed_byte_length and any(seed), "journal_seed_shape_mismatch")
        private["seed"] = seed
    elif stage == "security_key":
        parse_key_response(pdu)
        _need(verify_security_access(private["seed"], request[10:], as_public_key, module=module), "journal_AS_verification_failed")
    elif stage.startswith("write_") and stage != "write_cps":
        address = int(stage[6:], 16)
        _need(request == frame(group_write_request(address, dict(prepared.candidate.groups)[address], module=module)),
              "journal_candidate_request_mismatch")
        parse_group_write_response(pdu, address, module=module)
    elif stage == "check_signature":
        _need(parse_signature_check_response(pdu) is True, "journal_signature_routine_failed")
    elif stage == "write_cps":
        _need(request == frame(cps_write_request(expected_cps)), "journal_CPS_request_mismatch")
        parse_cps_write_response(pdu)
    elif stage in ("read_cps", "post_cps", "current_cps"):
        parse_cps_read_response(pdu, expected_cps)
        if stage == "post_cps":
            private["returned_cps"] = pdu[3:]
    elif stage == "reset":
        parse_reset_response(pdu)
    elif stage == 'default_session':
        parse_session_response(pdu, 1, layout=profile.session_layout)
    elif stage == "post_ping":
        ping = parse_ping_response(pdu, layout="f186_state")
        _need(ping.session == 1 and ping.state == 0x81, "journal_post_reset_ping_state")


def validate_journal(directory: Path, *, expected_context: dict, prepared: PreparedCoding | None,
                     as_public_key: RSA1024PublicKey | None, expected_vin: str, expected_svk: bytes,
                     expected_cps: bytes, profile: object, manifest_sha256: str | None = None) -> dict[str, object]:
    """Reparse stored originals with caller-supplied RAM facts; never replay them."""
    _context, requests, receipts, connections, seal = _reopen(directory, expected_context, manifest_sha256)
    module = _context.get('module', 'HU'); spec = contract(module)
    coding, post = transaction_stages(module); stages = coding + post
    def checked(facts: dict) -> dict:
        if seal is not None:
            _need(_json(seal["facts"]) == _json(facts), "journal_sealed_facts_mismatch")
        return facts
    confirmed = 0; full = 0; uncertain = False
    for row in requests:
        count = row.get("accepted_bytes")
        _need(count is None or (type(count) is int and 0 <= count <= row["byte_length"]), "journal_original_send_count")
        _need("uncertain" not in row or type(row["uncertain"]) is bool, "journal_original_send_uncertainty")
        confirmed += 0 if count is None else count
        full += int(count == row["byte_length"] and row.get("uncertain") is False)
        uncertain |= count is None or row.get("uncertain") is not False
    facts = {"request_intents": len(requests), "confirmed_application_bytes": confirmed,
             "recorded_attempt_results": sum("accepted_bytes" in row for row in requests),
             "full_requests_confirmed": full, "received_chunks": len(receipts),
             "received_bytes": sum(row["byte_length"] for row in receipts),
             "connection_intents": len(connections),
             "connections_opened": sum("opened" in state for state in connections.values()),
             "transmission_uncertain": uncertain,
             "close_uncertain": any("closed" not in state or state["closed"].get("uncertain") is not False for state in connections.values()),
             "mutation_may_have_occurred": any(row["stage"].startswith("write_") or row["stage"] == "reset" for row in requests),
             "complete_data_verified": False, "original_validation": "partial_no_success_claim",
             "persistence_established": False, "recovery_established": False,
             "effect_verified_on_car": False, "storage_is_send_authority": False}
    if len(requests) != len(stages) or full != len(stages) or uncertain or facts["close_uncertain"]:
        return checked(facts)
    try:
        _need(type(prepared) is PreparedCoding and type(as_public_key) is RSA1024PublicKey,
              "journal_verification_facts_missing")
        PreparedCoding.__post_init__(prepared)
        _need(prepared.edit.module == module, 'journal_preparation_module_mismatch')
        if 'selected_edit' in _context:
            _need(_context['selected_edit'] == prepared.edit.summary(), 'journal_selected_edit_mismatch')
        _need(type(expected_vin) is str and re.fullmatch("[A-HJ-NPR-Z0-9]{17}", expected_vin)
              and type(expected_svk) is bytes and 0 < len(expected_svk) <= 4093
              and type(expected_cps) is bytes and expected_cps == expected_vin[-7:].encode("ascii"),
              "journal_identity_facts_shape")
        _need(profile.session_layout in ("p2_timing", "opaque_parameters")
              and type(profile.seed_byte_length) is int and 1 <= profile.seed_byte_length <= 4092,
              "journal_profile_shape")
        _need(set(connections) == {1, 2}, "journal_connection_set")
        for connection in (1, 2):
            state = connections[connection]
            _need(set(state) == {"connection_attempted", "opened", "closed"}, "journal_connection_events")
            start, opened, closed = (state[k]["at"] for k in ("connection_attempted", "opened", "closed"))
            _need(all(_time(t) for t in (start, opened, closed)) and start <= opened <= closed
                  and opened - start <= 3 and closed - start < 30, "journal_connection_timing")
        _need(connections[2]["connection_attempted"]["at"] - connections[1]["closed"]["at"] >= (30 if module == 'HU' else 0)
              and connections[1]["closed"]["at"] < 30 and connections[2]["closed"]["at"] < 90,
              "journal_reconnect_timing")
        private = {}; pending_total = 0
        previous_terminal = {1: connections[1]["opened"]["at"], 2: connections[2]["opened"]["at"]}
        for index, row in enumerate(requests):
            connection = 1 if index < len(coding) else 2
            _need(row["connection"] == connection and row.get("outcome") == "positive"
                  and row.get("nrc") is None and type(row.get("pending_count")) is int
                  and 0 <= row["pending_count"] <= 4, "journal_completion_mismatch")
            started, sent = row["at"], row.get("send_at")
            _need(_time(started) and _time(sent) and previous_terminal[connection] <= started <= sent
                  and sent < started + 6, "journal_request_timing")
            parser = IncrementalParser(max_body_length=4096)
            deadline = min(started + 6, sent + 3); ack = positive = False; pending = 0; terminal = sent
            for receipt in receipts:
                if receipt["token"] != row["token"]:
                    continue
                at = receipt["at"]
                _need(_time(at) and terminal <= at < deadline
                      and at <= connections[connection]["closed"]["at"], "journal_response_timing")
                terminal = at
                for incoming in parser.feed(receipt["raw"]):
                    _need(not positive, "journal_trailing_frame")
                    if incoming.control is Control.ACK:
                        _need(not ack and (incoming.source, incoming.target) == (0xF4, row["raw"][7])
                              and incoming.diagnostic_payload == expected_ack_echo(row["raw"][8:]), "journal_ACK_mismatch")
                        ack = True
                    else:
                        _need(incoming.control is Control.DIAGNOSTIC
                              and (incoming.source, incoming.target) == (row["raw"][7], 0xF4), "journal_application_address")
                        pdu = incoming.diagnostic_payload
                        if pdu[:1] == b"\x7f":
                            _need(negative_response(pdu, row["raw"][8]) == 0x78, "journal_negative_response")
                            pending += 1; _need(pending <= 4, "journal_pending_limit")
                            deadline = min(started + 6, at + 3)
                        else:
                            _need(ack, "journal_positive_without_ACK")
                            _positive(row["stage"], pdu, row["raw"], prepared, as_public_key,
                                      expected_vin, expected_svk, expected_cps, profile, private)
                            positive = True
            parser.finish()
            _need(positive and pending == row["pending_count"], "journal_missing_positive")
            pending_total += pending
            previous_terminal[connection] = terminal
        _need(verify_coding1(prepared.original.signing_input, prepared.original.signature, prepared._verification_key, module=module)
              and verify_coding1(prepared.candidate.signing_input, prepared.candidate.signature, prepared._verification_key, module=module),
              "journal_original_or_candidate_signature")
        readback = CodingSnapshot(tuple(private["readback"]), prepared.original.provenance, spec.cafd, spec.btld)
        verify_coding_readback(prepared, readback, expected_cps=expected_cps, returned_cps=private["returned_cps"])
        facts.update(complete_data_verified=True, original_validation="complete_strict_originals_verified",
                     complete_readback_group_count=len(spec.groups), original_signature_verified=True,
                     candidate_signature_verified=True, AS_signature_verified=True,
                     returned_signature_verified=True,
                     ACK_count=len(stages), positive_count=len(stages), pending_count=pending_total, timing_complete=True)
        facts['CPS_matches_before_and_after_reset' if module == 'HU' else 'CPS_matches_before_and_after_default_session'] = True
    except (JournalError, CodingProtocolError, HSFZError, ValueError, KeyError, TypeError, AttributeError):
        facts["original_validation"] = "originals_do_not_establish_complete_success"
    return checked(facts)

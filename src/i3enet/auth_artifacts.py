"""Private raw session/security exchanges; never retain private signing keys."""
from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

from . import __version__
from .artifacts import ArtifactError, DiscoveryArtifactStore
from .auth_evidence import (SCHEMA, MODES, AuthSessionEvidence, auth_stages,
                            source_links, validate_capture)
from .evidence import EvidenceError, GatewayVINReadEvidence
from .svk import HeadUnitSVKEvidence

if TYPE_CHECKING:
    from .live_head_unit_auth import HeadUnitAuthResult


class HeadUnitAuthenticationArtifactStore(DiscoveryArtifactStore):
    """Prepare storage before keys/sockets; retain all actual attempted frames.

    Session replies and challenge are private evidence.
    No material importer, private key or arbitrary message API is exposed.
    """
    _category = "head-unit-auth"

    def save_auth(self, result: HeadUnitAuthResult, report: dict[str, object],
                  identity: GatewayVINReadEvidence, svk: HeadUnitSVKEvidence, *,
                  session_evidence: AuthSessionEvidence | None = None,
                  as_public_key=None) -> dict[str, object]:
        try:
            expected_category = ('bdc-auth-validation' if result.mode == 'validate_bdc_auth'
                                 else {'HU':'head-unit-auth','BDC':'bdc-auth','VSG01':'vsg-auth'}[result.module])
            if self._category != expected_category:
                raise ArtifactError('authentication_store_module_mismatch')
            if len(result.request_bytes) != len(result.request_started_after_seconds):
                raise ArtifactError("authentication request attribution incomplete")
            if len(result.recv_chunks) != len(result.chunk_stage_names):
                raise ArtifactError("authentication receive attribution incomplete")
            requests = []
            stages = auth_stages(result.mode)
            if len(result.request_bytes) > len(stages):
                raise ArtifactError("authentication request budget invalid")
            for index, raw in enumerate(result.request_bytes):
                name = f"request-{index + 1:02d}.bin"
                self._write(name, raw)
                requests.append({"file": name, "stage": stages[index], "byte_length": len(raw),
                                 "sha256": hashlib.sha256(raw).hexdigest(),
                                 "started_after_seconds": result.request_started_after_seconds[index],
                                 "meaning": "complete attempted frame; send counters establish accepted bytes"})
            chunks = []
            for index, (chunk, stage) in enumerate(zip(result.recv_chunks, result.chunk_stage_names)):
                name = f"recv-{index + 1:02d}.bin"
                self._write(name, chunk.data)
                chunks.append({"file": name, "stage": stage, "byte_length": len(chunk.data),
                               "sha256": hashlib.sha256(chunk.data).hexdigest(),
                               "received_after_seconds": chunk.received_after_seconds})
            manifest = {
                "schema": SCHEMA, "implementation_version": __version__,
                "timestamp_utc": self.timestamp_utc, "private_raw_originals": True,
                "capture_scope": "application stream reads and attempted sends; not a link-layer capture",
                "requests": requests, "received_chunks": chunks, "report": report.copy(),
                "selected_session_layout": report.get("selected_session_layout"),
                **source_links(identity, svk),
            }
            if session_evidence is not None:
                manifest["source_session_probe"] = {
                    "manifest_sha256": session_evidence.manifest_sha256,
                    "session_layout": session_evidence.session_layout,
                }
            complete = (result.mode in MODES and result.outcome == MODES[result.mode][1])
            if complete:
                validate_capture(
                    manifest, result.request_bytes, tuple(chunk.data for chunk in result.recv_chunks),
                    mode=result.mode, identity=identity, svk=svk,
                    session_layout=report.get("selected_session_layout"),
                    session_evidence=session_evidence,
                    as_public_key=as_public_key,
                )
                manifest["original_stream_validation"] = "passed"
            else:
                manifest["original_stream_validation"] = "incomplete_no_success_claim"
            encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
            self._write("manifest.json", encoded)
            return {
                "directory": str(self.directory), "manifest_sha256": hashlib.sha256(encoded).hexdigest(),
                "requests_saved": len(requests), "received_chunks_saved": len(chunks),
                "received_bytes_saved": sum(item["byte_length"] for item in chunks),
                "all_received_bytes_saved": True, "complete_original_stream_validated": complete,
                "requests": [{k: row[k] for k in ("file", "stage", "byte_length", "sha256")} for row in requests],
                "received_chunks": chunks,
            }
        except (OSError, EvidenceError, ValueError, TypeError, AttributeError) as exc:
            raise ArtifactError("authentication original retention failed; stop before further traffic") from exc


class BDCAuthenticationArtifactStore(HeadUnitAuthenticationArtifactStore):
    _category = 'bdc-auth'


class VSGAuthenticationArtifactStore(HeadUnitAuthenticationArtifactStore):
    _category = 'vsg-auth'


class BDCAuthenticationValidationArtifactStore(HeadUnitAuthenticationArtifactStore):
    _category = 'bdc-auth-validation'

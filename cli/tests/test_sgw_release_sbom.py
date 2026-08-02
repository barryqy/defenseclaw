# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import shutil
import zipfile
from pathlib import Path

import pytest

from cli.tests.test_windows_installer_artifacts import SGW_CORE_TERMS, _fixture
from scripts import release_candidate, release_certification, stage_sgw_modules, windows_installer_artifacts


def test_sgw_release_generators_and_sbom_tests_are_certification_sensitive() -> None:
    policy = json.loads((release_candidate.ROOT / "release/certification-policy.json").read_text(encoding="utf-8"))
    sensitive = set(policy["release_sensitive_paths"])

    assert {
        "LICENSE",
        "NOTICE",
        "setup.py",
        "defenseclaw_build_backend.py",
        "scripts/windows_installer_artifacts.py",
        "cli/tests/test_windows_installer_artifacts.py",
        "cli/tests/test_sgw_release_sbom.py",
    } <= sensitive
    for path in (
        "LICENSE",
        "NOTICE",
        "setup.py",
        "defenseclaw_build_backend.py",
        "scripts/windows_installer_artifacts.py",
        "cli/tests/test_sgw_release_sbom.py",
        "cli/tests/test_windows_installer_artifacts.py",
    ):
        assert release_certification._is_sensitive([path], list(sensitive))


def test_sgw_sbom_is_a_required_runtime_and_release_asset_from_0811() -> None:
    version = "0.8.11"
    protected_wheel = release_candidate._expected_release_artifacts(version)["wheel"]
    sbom = f"{protected_wheel}.sbom.json"

    assert release_candidate.sgw_sbom_asset_name("0.8.10") is None
    assert release_candidate.sgw_sbom_asset_name(version) == sbom
    assert sbom in release_candidate.runtime_asset_names(version)
    assert sbom in release_candidate.payload_asset_names(version, "notarized")
    assert sbom in release_candidate.published_asset_names(version, "notarized")


def test_runtime_validator_binds_sgw_sbom_to_protected_wheel(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    version = fixture.version
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    canonical = runtime / f"defenseclaw-{version}-py3-none-any.whl"
    shutil.copy2(fixture.payload_root / canonical.name, canonical)
    protected_name = release_candidate._expected_release_artifacts(version)["wheel"]
    release_candidate._write_protected_artifact(canonical, runtime / protected_name)
    sbom_name = release_candidate.sgw_sbom_asset_name(version)
    assert sbom_name is not None
    shutil.copy2(fixture.sgw_sbom, runtime / sbom_name)

    release_candidate._validate_sgw_runtime_sbom(runtime, version)

    document = json.loads((runtime / sbom_name).read_text(encoding="utf-8"))
    document["files"] = document["files"][1:]
    (runtime / sbom_name).write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(release_candidate.CandidateError, match="incomplete or differs"):
        release_candidate._validate_sgw_runtime_sbom(runtime, version)


def test_release_workflow_authenticates_sgw_sbom_before_runtime_sealing() -> None:
    workflow = (release_candidate.ROOT / ".github/workflows/release.yaml").read_text(encoding="utf-8")
    generate = workflow.index("scripts/stage_sgw_modules.py generate-sbom")
    verify = workflow.index("scripts/stage_sgw_modules.py verify-sbom", generate)
    prepare = workflow.index("scripts/release_candidate.py prepare-runtime", verify)

    assert "--authenticate" in workflow[verify:prepare]
    assert generate < verify < prepare


def test_core_license_text_must_be_actual_terms_not_a_pointer() -> None:
    with pytest.raises(stage_sgw_modules.DeliveryError, match="placeholder"):
        stage_sgw_modules.validated_core_license_text(
            "The proprietary license terms supplied separately are a placeholder for the approved artifact."
        )

    terms = (
        "Permission is granted to run s-gw Core with an authenticated DefenseClaw distribution. "
        "No redistribution rights are granted by these test license terms."
    )
    assert stage_sgw_modules.validated_core_license_text(terms) == terms


def test_sgw_sbom_rejects_wheel_metadata_that_does_not_declare_core_license(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    source = fixture.payload_root / f"defenseclaw-{fixture.version}-py3-none-any.whl"
    tampered = tmp_path / "tampered.whl"
    with zipfile.ZipFile(source) as source_archive, zipfile.ZipFile(tampered, "w") as output:
        for info in source_archive.infolist():
            payload = source_archive.read(info)
            if info.filename.endswith(".dist-info/METADATA"):
                payload = payload.replace(
                    f"License-Expression: {stage_sgw_modules.SGW_MIXED_LICENSE}\n".encode(),
                    b"License-Expression: Apache-2.0\n",
                )
            output.writestr(info, payload)

    with pytest.raises(stage_sgw_modules.DeliveryError, match="license expression is inconsistent"):
        stage_sgw_modules._build_sgw_sbom(
            tampered,
            version=fixture.version,
            source_commit=fixture.source_commit,
            source_epoch=fixture.source_epoch,
            authenticate=False,
        )


@pytest.mark.parametrize("change", ["missing", "tampered"])
def test_wheel_license_validator_rejects_missing_or_tampered_license(tmp_path: Path, change: str) -> None:
    fixture = _fixture(tmp_path)
    source = fixture.payload_root / f"defenseclaw-{fixture.version}-py3-none-any.whl"
    tampered = tmp_path / f"{change}-license.whl"

    with zipfile.ZipFile(source) as source_archive, zipfile.ZipFile(tampered, "w") as output:
        for info in source_archive.infolist():
            payload = source_archive.read(info)
            if info.filename.endswith(".dist-info/licenses/LICENSE"):
                if change == "missing":
                    continue
                payload = bytes([payload[0] ^ 1]) + payload[1:]
            output.writestr(info, payload)

    expected = "lacks its exact license files" if change == "missing" else "LICENSE differs from the source"
    with pytest.raises(stage_sgw_modules.DeliveryError, match=expected):
        stage_sgw_modules._validate_wheel_license_metadata(
            tampered,
            version=fixture.version,
            core_terms=SGW_CORE_TERMS,
        )


@pytest.mark.parametrize("record_change", ["missing", "corrupt"])
@pytest.mark.parametrize("member_kind", ["METADATA", "LICENSE", "NOTICE"])
def test_wheel_license_validator_rejects_bad_record_rows(
    tmp_path: Path,
    record_change: str,
    member_kind: str,
) -> None:
    fixture = _fixture(tmp_path)
    source = fixture.payload_root / f"defenseclaw-{fixture.version}-py3-none-any.whl"
    tampered = tmp_path / f"{record_change}-{member_kind.lower()}-record.whl"

    with zipfile.ZipFile(source) as source_archive:
        metadata_name = next(name for name in source_archive.namelist() if name.endswith(".dist-info/METADATA"))
        dist_info = Path(metadata_name).parent.as_posix()
        selected = {
            "METADATA": metadata_name,
            "LICENSE": f"{dist_info}/licenses/LICENSE",
            "NOTICE": f"{dist_info}/licenses/NOTICE",
        }[member_kind]
        record_name = f"{dist_info}/RECORD"
        with zipfile.ZipFile(tampered, "w") as output:
            found = False
            for info in source_archive.infolist():
                payload = source_archive.read(info)
                if info.filename == record_name:
                    rows = []
                    for row in payload.decode("utf-8").splitlines():
                        name, digest_value, size = row.split(",", 2)
                        if name != selected:
                            rows.append(row)
                            continue
                        found = True
                        if record_change == "corrupt":
                            rows.append(f"{name},sha256={'A' * 43},{size}")
                    payload = ("\n".join(rows) + "\n").encode("utf-8")
                output.writestr(info, payload)
            assert found

    expected = "absent from RECORD" if record_change == "missing" else "RECORD entry is inconsistent"
    with pytest.raises(stage_sgw_modules.DeliveryError, match=expected):
        stage_sgw_modules._validate_wheel_license_metadata(
            tampered,
            version=fixture.version,
            core_terms=SGW_CORE_TERMS,
        )


def test_release_validator_requires_exact_imported_sgw_inventory(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    windows_installer_artifacts.build_sbom(fixture)
    manifest_path = fixture.payload_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    def sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    provenance = {
        "inputs": {
            "embedded_payload_sha256": sha256(fixture.embedded_payload),
            "payload_files": manifest["files"],
            "payload_manifest_sha256": sha256(manifest_path),
            "wheel": manifest["wheel"],
            "wheel_sha256": manifest["files"][manifest["wheel"]],
            "sgw_sbom_sha256": sha256(fixture.sgw_sbom),
        }
    }
    release_candidate._validate_windows_setup_sbom(
        fixture.output,
        version=fixture.version,
        commit=fixture.source_commit,
        setup_sha256=sha256(fixture.setup),
        provenance=provenance,
    )

    document = json.loads(fixture.output.read_text(encoding="utf-8"))
    npm_root = next(
        package
        for package in document["packages"]
        if str(package.get("comment", "")).startswith("DefenseClaw s-gw inventory role=npm-root")
    )
    npm_root["licenseDeclared"] = stage_sgw_modules.SGW_CORE_LICENSE
    fixture.output.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(release_candidate.CandidateError, match="npm root license"):
        release_candidate._validate_windows_setup_sbom(
            fixture.output,
            version=fixture.version,
            commit=fixture.source_commit,
            setup_sha256=sha256(fixture.setup),
            provenance=provenance,
        )

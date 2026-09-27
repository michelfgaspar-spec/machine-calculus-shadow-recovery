"""Verify the inherited signed source identity; no source assembly or signing."""
import base64
import binascii
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
from .common import BuildError, _unique_pairs, read_bytes, relative_path


NAMESPACE = "machine-calculus-shadows-watermark-v1"
PRINCIPAL = "machine-calculus-shadows"
EDITION = "structural-2026-09-26"
MANIFEST = "watermark/manifest.json"
SIGNATURE = MANIFEST + ".sig"
PUBLIC_KEY = "watermark/signing-key.pub"
BUNDLE_PATHS = (MANIFEST, SIGNATURE, PUBLIC_KEY)
HEADER_LINES = 8
_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")



def _match(value, pattern, label):
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise BuildError("Invalid watermark " + label)
    return value


def _marked_path(value):
    value = relative_path(value)
    if any(ord(char) < 32 or ord(char) > 126 for char in value):
        raise BuildError("Watermark paths must contain printable ASCII only")
    return value


def _identity(manifest):
    if not isinstance(manifest, dict):
        raise BuildError("Watermark manifest must be an object")
    if type(manifest.get("schema_version")) is not int or manifest["schema_version"] != 1:
        raise BuildError("Expected watermark schema_version 1")
    if manifest.get("record_kind") != "source-watermark-v1" or manifest.get("edition") != EDITION:
        raise BuildError("Unknown watermark record kind or edition")
    _match(manifest.get("watermark_id"), r"MC-[0-9a-f]{32}", "ID")
    _match(manifest.get("repository_url"),
           r"https://github\.com/[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9_.-]*",
           "repository URL")
    _match(manifest.get("canonical_source_commit"), r"[0-9a-f]{40}", "source commit")
    signing = manifest.get("signing")
    if not isinstance(signing, dict) or set(signing) != {
            "namespace", "principal", "public_key_fingerprint"}:
        raise BuildError("Invalid watermark signing fields")
    if signing["namespace"] != NAMESPACE or signing["principal"] != PRINCIPAL:
        raise BuildError("Unexpected watermark signature namespace or principal")
    _match(signing["public_key_fingerprint"], _FINGERPRINT, "signing fingerprint")


def _file_map(value, label, tex=False):
    if not isinstance(value, dict) or not value:
        raise BuildError("Watermark needs a nonempty " + label + " map")
    for path, expected in value.items():
        _marked_path(path)
        _match(expected, r"[0-9a-f]{64}", label + " SHA-256")
        if tex and not path.endswith(".tex"):
            raise BuildError("Watermark output must be a .tex file: " + path)
        if any(str(parent) in value for parent in PurePosixPath(path).parents):
            raise BuildError("Conflicting watermark file paths: " + path)


def _validate(manifest):
    _identity(manifest)
    expected_fields = {"schema_version", "record_kind", "watermark_id", "repository_url",
                       "canonical_source_commit", "edition", "signing", "source_files",
                       "canonical_outputs", "marked_outputs"}
    if set(manifest) != expected_fields:
        raise BuildError("Unexpected watermark manifest fields")
    _file_map(manifest["source_files"], "source_files")
    for key in ("canonical_outputs", "marked_outputs"):
        _file_map(manifest[key], key, tex=True)
        if len(manifest[key]) != 29:
            raise BuildError("The canonical edition requires 29 watermark output files")
    if set(manifest["canonical_outputs"]) != set(manifest["marked_outputs"]):
        raise BuildError("Canonical and marked output paths differ")
    if set(manifest["source_files"]).intersection(BUNDLE_PATHS):
        raise BuildError("The signature bundle cannot hash itself")


def _run(command, data=None):
    try:
        result = subprocess.run(command, input=data, capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise BuildError("Cannot run watermark signature checker: " + str(exc)) from exc
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()[:500]
        raise BuildError("Watermark signature check failed: " + detail)
    return result.stdout


def _public_line(raw):
    try:
        line = raw.decode("ascii").strip()
        parts = line.split()
        if "\n" in line or "\r" in line or len(parts) < 2 or parts[0] != "ssh-ed25519":
            raise ValueError("Expected one Ed25519 public key")
        base64.b64decode(parts[1], validate=True)
    except (UnicodeError, ValueError, binascii.Error) as exc:
        raise BuildError("Invalid watermark public key; private keys are never accepted") from exc
    return " ".join(parts[:2])


def _bundle(root, expected_fingerprint):
    raw = read_bytes(root, MANIFEST)
    try:
        manifest = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BuildError("Invalid watermark manifest JSON") from exc
    _validate(manifest)
    if expected_fingerprint is not None:
        _match(expected_fingerprint, _FINGERPRINT, "trusted fingerprint")
    bundle = {MANIFEST: raw, SIGNATURE: read_bytes(root, SIGNATURE),
              PUBLIC_KEY: read_bytes(root, PUBLIC_KEY)}
    public_line = _public_line(bundle[PUBLIC_KEY])
    executable = shutil.which("ssh-keygen")
    if not executable:
        raise BuildError("ssh-keygen is required for watermark signature verification")
    # Snapshot only public data, so all signature operations use the same bytes.
    with tempfile.TemporaryDirectory(prefix="source-watermark-verify-") as temporary:
        directory = Path(temporary)
        public = directory / "signing-key.pub"
        public.write_text(public_line + "\n", encoding="ascii")
        output = _run([executable, "-l", "-f", str(public), "-E", "sha256"])
        fields = output.decode("ascii", errors="replace").split()
        if len(fields) < 2 or not _FINGERPRINT.fullmatch(fields[1]):
            raise BuildError("ssh-keygen returned an unusable public-key fingerprint")
        fingerprint = fields[1]
        if fingerprint != manifest["signing"]["public_key_fingerprint"]:
            raise BuildError("Bundled public key differs from the signed fingerprint")
        if expected_fingerprint is not None and fingerprint != expected_fingerprint:
            raise BuildError("Watermark key differs from the independently trusted fingerprint")
        signers = directory / "allowed-signers"
        signers.write_text(PRINCIPAL + ' namespaces="' + NAMESPACE + '" ' + public_line + "\n",
                           encoding="ascii")
        signature = directory / "manifest.sig"
        signature.write_bytes(bundle[SIGNATURE])
        _run([executable, "-Y", "verify", "-f", str(signers), "-I", PRINCIPAL,
              "-n", NAMESPACE, "-s", str(signature)], raw)
    return manifest, bundle, fingerprint

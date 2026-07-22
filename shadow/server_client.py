"""shadow/server_client.py: the client-side transport half of Phase 5
(wiring the hardened client to the Phase 4 zero-trust server).

Phase 4 (the server component) stood up a server that never sees raw content and
never returns anything but a fixed-shape, EDGE-SIGNED receipt (see
the edge Worker's request handler and receipt module). THIS module is the one
place in shadow/ that talks to that server over the network: it POSTs an
already-signed envelope (shadow.signing.sign_bundle's output, built over
shadow.bundle.assemble_bundle's output) to the Worker's `/submit` endpoint,
and hands back either a VERIFIED signed receipt or a NoReceipt sentinel.
Nothing here re-scores, re-signs the customer's own bundle, or trusts a
response before checking its signature.

THE SERVER, PRECISELY: `server_url` here is the edge Worker's origin (e.g.
"https://edge.muninn.example" locally "http://127.0.0.1:8787"), NOT the
Python scoring backend's own origin -- that backend (its own tree)
is an internal implementation detail the Worker calls into over its own
BACKEND_ORIGIN var; a client never talks to it directly. This module POSTs
the envelope UNWRAPPED (just {"bundle": ..., "signature": ...}, no
public_pem alongside it) to f"{server_url}/submit", matching index.ts's own
request shape exactly -- the Worker resolves which public key applies by
looking up envelope.signature.key_id in its own D1 table (a customer
registers a public key with the server out of band, once; it is never sent
on every request).

TWO DIFFERENT SIGNATURES, TWO DIFFERENT KEYS -- do not confuse them:
  1. shadow.signing.sign_bundle()/verify_envelope() -- the CUSTOMER's own
     ed25519 key, over the bundle+envelope. Verified SERVER-side (by the
     Python backend, see its app module) before
     any scoring runs. This module does not touch that signature at all --
     it only ever produces (via shadow.signing, called by shadow.pr_action)
     an already-signed envelope to send.
  2. THIS module's own verify_receipt() -- the EDGE WORKER's own ed25519
     key (env.RECEIPT_SIGNING_KEY_JWK, a Worker Secret, never the
     customer's key), over the receipt the Worker composed
     (the edge Worker's receipt module's canonicalReceiptBytes shape:
     {schema_version, request_id, key_id, verdict, scores, ts}). Verified
     CLIENT-side, here, before shadow.pr_action ever renders or posts
     anything. This is the signature a caller pins MUNINN_SERVER_PUBKEY
     against.

FAIL-CLOSED, TWO DIFFERENT WAYS ON PURPOSE (see shadow.pr_action.run() for
how a caller must treat each):
  - Anything short of "the server responded 200 with a well-formed,
    correctly-signed receipt" that is a TRANSPORT/protocol-shape problem
    (unreachable, timeout, non-2xx, not JSON, missing a required field) is
    NOT an error here -- it returns the NoReceipt sentinel. A caller
    degrades gracefully: log it, post no comment, exit clean. A customer's
    CI must never fail merely because the scoring server had a bad moment.
  - A response that IS receipt-shaped (every required field present) but
    whose signature does NOT verify against the configured/pinned server
    public key is a SECURITY EVENT, not a soft skip: submit_envelope raises
    ServerSignatureError, and a caller must refuse to post anything and
    fail the step loudly. A forged or corrupted receipt is exactly the
    thing a signature exists to catch; silently discarding it like a
    NoReceipt would defeat the point of verifying at all.

STDLIB-ONLY TRANSPORT: `urllib.request` for the POST (matching shadow/
gh_client.py's own stdlib-only HTTP convention), `cryptography` only for the
verify step it already needed anyway (shadow/signing.py is already the
repo's one place that imports it; this module reuses that same primitive,
it does not add a new dependency).
"""
from __future__ import annotations

import base64
import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

log = logging.getLogger("muninn.server_client")

# The Worker's own /submit path (the edge Worker's request handler). A
# caller passes the SERVER'S ORIGIN (e.g. "http://127.0.0.1:8787"); this
# module appends this fixed path, the same way the Worker itself appends
# "/score" to its own configured BACKEND_ORIGIN.
SUBMIT_PATH = "/submit"

# Must match the edge Worker's receipt module's RECEIPT_SCHEMA_VERSION
# constant exactly -- this is a version check, not a magic string chosen
# independently on this side of the wire.
RECEIPT_SCHEMA_VERSION = "receipt-v1"

DEFAULT_TIMEOUT_SECONDS = 10.0

# Explicit, non-urllib User-Agent (pen-test INFO finding, 2026-07): Cloudflare
# edge bot-management 403s the urllib default UA ("Python-urllib/3.x") on
# workers.dev BEFORE the Worker itself ever runs, so a real customer CI could
# get a spurious 403 here that this module would otherwise fold into a plain
# NoReceipt("http_status_403") -- indistinguishable from an actual server
# rejection. A distinct, identifiable UA avoids tripping that edge rule.
USER_AGENT = "muninn-action/1.0"

# Every field the edge Worker's receipt module's SignedReceipt interface
# guarantees on a 200 response. A response missing even one of these is not
# receipt-shaped at all (see module docstring: that is a NoReceipt, not a
# ServerSignatureError -- there is no signature to have failed).
_REQUIRED_RECEIPT_FIELDS = (
    "schema_version", "request_id", "key_id", "verdict", "scores", "ts", "sig",
)


class ServerSignatureError(Exception):
    """Raised ONLY when the server responded with a receipt-shaped body
    (every field in _REQUIRED_RECEIPT_FIELDS present) whose ed25519
    signature does NOT verify against the configured/pinned server public
    key. This is a security event (a forged/corrupted receipt, or a
    misconfigured/wrong pinned key) -- a caller must never catch this and
    post anyway; see shadow.pr_action.run()'s server-mode branch, which lets
    this propagate and fails the step loudly."""


@dataclass(frozen=True)
class NoReceipt:
    """Sentinel: server mode ran, but no receipt is available this run. Never
    raised -- returned so a caller can degrade gracefully (log, post no
    comment, exit clean) exactly like a non-AI-authored PR already does
    elsewhere in shadow/pr_action.py. `reason` is a short machine-readable
    code for the log line / tests, never a value derived from bundle
    content."""
    reason: str


SubmitResult = Union[Dict[str, Any], NoReceipt]


def _canonical_receipt_bytes(fields: Dict[str, Any]) -> bytes:
    """The exact byte shape the edge Worker's receipt module's own
    canonicalReceiptBytes()/sortKeysDeep() sign: the object
    {schema_version, request_id, key_id, verdict, scores, ts} (deliberately
    NOT including `sig` itself), JSON-encoded with keys sorted at every
    nesting level and no incidental whitespace.

    json.dumps(sort_keys=True) already sorts nested dict keys recursively
    (not just the top level), matching sortKeysDeep's recursive walk;
    separators=(",", ":") matches JSON.stringify's own compact (no-space)
    output; ensure_ascii=False matches shadow.signing's own convention (in
    practice every field here -- a UUID, a key id, "accepted"/"rejected", an
    ISO-8601 stamp, and scores built only from ASCII pointer tokens and
    counts -- is already pure ASCII, so this choice has no observable
    effect today, but it is the same choice made everywhere else in this
    codebase for the same reason).

    This is a SEPARATE canonicalization from shadow.signing's own bundle-
    signing rules on purpose: a different artifact (the edge's receipt, not
    the customer's bundle+envelope) signed by a different key (the edge's
    own Worker Secret, not the customer's). There is no byte-parity
    requirement between the two, so this function does not reuse
    shadow.signing._canonical_bundle_bytes."""
    obj = {
        "schema_version": fields["schema_version"],
        "request_id": fields["request_id"],
        "key_id": fields["key_id"],
        "verdict": fields["verdict"],
        "scores": fields["scores"],
        "ts": fields["ts"],
    }
    # GitHub App identity binding (the edge Worker's receipt module,
    # canonicalReceiptBytes): the Worker includes `installation` in the signed
    # bytes ONLY when the submitting key is bound to a verified installation; a
    # legacy self-asserted-key receipt omits the key ENTIRELY (not null), so its
    # canonical bytes stay identical to a pre-installation receipt. We must
    # mirror that conditional inclusion exactly, using the same sub-object field
    # names (installation_id, account_login), or every bound-key receipt fails
    # verification here while every unbound one keeps working. sort_keys=True
    # sorts these nested keys the same way sortKeysDeep does on the Worker side,
    # so no manual ordering is needed.
    installation = fields.get("installation")
    if isinstance(installation, dict):
        obj["installation"] = {
            "installation_id": installation["installation_id"],
            "account_login": installation["account_login"],
        }
    return json.dumps(
        obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")


def verify_receipt(receipt: Dict[str, Any], server_public_pem: bytes) -> bool:
    """Fail-closed verification of a server-signed receipt's ed25519
    signature, mirroring shadow.signing.verify_envelope()'s own
    never-raises-past-this-boundary discipline: a malformed receipt, a bad
    base64 sig, a wrong key type, or an actual signature mismatch all return
    False, never raise. True means, and only means, that the exact
    schema_version/request_id/key_id/verdict/scores/ts combination present
    in `receipt` was signed by the holder of the private key matching
    `server_public_pem` -- it says nothing about whether that key belongs to
    the server a caller thinks it does (that is what pinning
    MUNINN_SERVER_PUBKEY is for) and nothing about the freshness of
    `request_id`/`ts` (this run's nonce/replay enforcement already happened
    server-side, at the edge, before this receipt was ever composed)."""
    try:
        for field in _REQUIRED_RECEIPT_FIELDS:
            if field not in receipt:
                return False
        if receipt.get("schema_version") != RECEIPT_SCHEMA_VERSION:
            return False
        sig = receipt.get("sig")
        if not isinstance(sig, str):
            return False
        sig_bytes = base64.b64decode(sig, validate=True)
        public_key = serialization.load_pem_public_key(server_public_pem)
        if not isinstance(public_key, Ed25519PublicKey):
            return False
        payload = _canonical_receipt_bytes(receipt)
        public_key.verify(sig_bytes, payload)
        return True
    except Exception:
        # fail closed: anything short of a clean, verified signature reads
        # as "not verified", never raises out of this function.
        return False


def _post_json(url: str, body: bytes, timeout: float) -> Optional[tuple]:
    """Real HTTP POST, urllib-only. Returns (status, raw_bytes) on any
    completed HTTP exchange (including a non-2xx one -- the caller decides
    what that means), or None on a transport-level failure (DNS, connect,
    timeout, connection reset). Never raises past this function."""
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        # HTTPError IS the response for a non-2xx status in urllib -- still
        # a completed exchange, not a transport failure.
        try:
            return exc.code, exc.read()
        except Exception:
            return exc.code, b""
    except Exception as exc:
        log.warning("muninn server request failed (transport error): %s", exc)
        return None


def submit_envelope(
    server_url: str,
    envelope: Dict[str, Any],
    *,
    server_public_pem: Optional[bytes],
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> SubmitResult:
    """POST a signed envelope (shadow.signing.sign_bundle's output) to the
    configured server's `/submit` endpoint and return a VERIFIED receipt
    dict, or the NoReceipt sentinel.

    Never raises for a transport failure or a non-receipt-shaped response --
    unreachable server, timeout, non-2xx status, non-JSON body, or a JSON
    body missing a required receipt field all degrade to NoReceipt (see
    module docstring). Raises ServerSignatureError ONLY when a receipt-
    shaped body's signature does not verify against `server_public_pem` --
    that is the one path a caller must NOT swallow.

    `server_public_pem` is the configured/pinned server (edge Worker)
    public key (env MUNINN_SERVER_PUBKEY, PEM-encoded ed25519). If it is not
    configured at all, this function refuses to trust ANY receipt sight
    unseen and returns NoReceipt immediately, without even attempting the
    request -- there is no real deployed default to pin against yet (Phase
    4 has not been deployed), so "no pinned key" must never silently mean
    "trust whatever comes back."."""
    if not server_public_pem:
        log.error(
            "MUNINN_SERVER_PUBKEY is not configured; refusing to submit to "
            "the scoring server at all, since any response could not be "
            "verified -- treating this run as 'no receipt'.")
        return NoReceipt("server_pubkey_not_configured")

    url = server_url.rstrip("/") + SUBMIT_PATH
    body = json.dumps(envelope).encode("utf-8")

    result = _post_json(url, body, timeout)
    if result is None:
        return NoReceipt("transport_error")
    status, raw = result

    if status != 200:
        log.warning(
            "muninn server returned non-200 status %s; no receipt this run",
            status)
        return NoReceipt(f"http_status_{status}")

    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        log.warning(
            "muninn server response was not valid JSON; no receipt this run")
        return NoReceipt("malformed_json")

    if not isinstance(parsed, dict) or any(
        f not in parsed for f in _REQUIRED_RECEIPT_FIELDS
    ):
        log.warning(
            "muninn server response is not a receipt-shaped object; "
            "no receipt this run")
        return NoReceipt("malformed_receipt_shape")

    if not verify_receipt(parsed, server_public_pem):
        raise ServerSignatureError(
            "muninn server returned a receipt whose signature does not "
            "verify against the configured MUNINN_SERVER_PUBKEY. Refusing "
            "to trust or post it. This is a security event (a forged or "
            "corrupted receipt, or a misconfigured/wrong pinned key), not a "
            "soft transport failure.")

    return parsed

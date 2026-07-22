"""shadow/signing.py: ed25519 signing for the Phase 2 fingerprint bundle
(Phase 3 of the server-side scoring-engine split).

Phase 2 (shadow/bundle.py) built a REDACTED FINGERPRINT BUNDLE that is safe
to leave the client (structural pointers and typed signal detections only,
never raw content, enforced by assert_no_forbidden_keys()). THIS phase adds
the layer a server needs before it can trust that bundle came from the
customer who registered a public key, and was not altered in transit: a
detached ed25519 signature wrapped around the bundle in a plain, still-
readable envelope.

Still fully local, still fully offline this phase: no network, no server.
generate_keypair() is the first-run keygen a customer runs once, locally; the
private key it returns is meant to become a repo secret (never transmitted,
never logged), the public key is the thing that eventually gets registered
with a server (a later phase, not this one).

WHY A NEW DEPENDENCY: Python's stdlib has no usable ed25519 signing
primitive (hashlib/hmac cover symmetric and hashing, not public-key
signatures). This module is the ONE place in the codebase that imports
`cryptography` (pinned exactly in requirements.txt at the repo root); every
other module stays stdlib-only.

DETACHED, NOT OPAQUE: the signed envelope is
    {"bundle": <the Phase 2 bundle object, byte-for-byte unchanged>,
     "signature": {"alg": "ed25519", "key_id": "<id>", "nonce": "<hex>",
                   "issued_at": "<iso8601>", "sig": "<base64>"}}
so a human or a diff tool can still read/diff the bundle directly; the
signature sits alongside it rather than swallowing it into an opaque blob.

THE SIGNATURE COVERS A PROTECTED HEADER, NOT JUST THE BUNDLE: alg, key_id,
nonce, and issued_at sit next to the signature in the envelope (so a reader
can see them without verifying), but every one of them is ALSO folded into
the signed payload alongside the bundle:
    {"alg": ..., "key_id": ..., "nonce": ..., "issued_at": ..., "bundle": ...}
canonicalized the same way as the bundle alone used to be. Before this,
key_id and alg sat outside the signature entirely -- an attacker could
relabel key_id (claim a different identity for an otherwise-valid envelope)
or swap alg, and verify_envelope() had no way to detect it from the
signature itself (only the separate `alg == ALG` name check caught a
tampered alg, and nothing caught a tampered key_id). Binding them into the
signed payload means ANY change to alg/key_id/nonce/issued_at/bundle
invalidates the signature, not just a change to the bundle.

nonce AND issued_at (fix for replay/freshness, CLIENT HALF ONLY): each
sign_bundle() call mints a fresh random nonce (secrets.token_hex(16), 128
bits) and stamps issued_at (ISO-8601, same --now/env/UTC-now resolution
order as shadow.doctor.resolve_now) into the signed payload. This phase
only makes those two fields part of what is signed and tamper-evident; it
does NOT enforce freshness or reject a replayed envelope -- there is no
server yet. A later phase's server holds a nonce cache and a freshness
window; this phase's job is only to make sure the fields that enforcement
will need are already on the wire and already authenticated.

CANONICAL SERIALIZATION: signing and verifying both hash the same
`_canonical_bundle_bytes()` shape (json.dumps with sort_keys=True,
ensure_ascii=False, separators=(",", ":"), allow_nan=False) -- the same
canonical-JSON shape shadow/review.py's _canonical_json already uses for
its own content fingerprint, now with allow_nan=False frozen in and a
round-trip check (see that function's docstring). Same input, same bytes,
every time, regardless of the in-memory dict's key insertion order. The
exact rules are also written down in docs/protocol-spec.md so a future
server-side implementation in a different language stays byte-identical.

FAIL CLOSED: verify_envelope() returns True only when every step (envelope
shape, base64 decoding, PEM parsing, key type, and the actual ed25519
signature check) succeeds and matches. Anything else -- a malformed
envelope, a corrupt signature, a wrong key, a tampered bundle -- returns
False. Nothing here raises past this module's boundary; a caller never has
to remember to wrap this in a try/except to be safe.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from shadow._bundle_primitives import resolve_now  # noqa: E402 -- for issued_at

ALG = "ed25519"
KEY_ID_PREFIX = "cust"
KEY_ID_VERSION = 1
NONCE_HEX_LEN = 32  # secrets.token_hex(16) -> 128 bits of randomness

# Domain-separation label for deriving the bundle pointer-tokenizer key from
# an ed25519 signing key's raw seed. A fixed, never-changing context string:
# changing it would silently reassign every customer's pointer key. This is
# the V1 (bundle-v1) derivation: a single plain HMAC-SHA256 over the seed.
# Kept UNCHANGED so bundles produced by already-deployed v0.1/v0.1.1 clients
# still reproduce byte-identical pointers.
_POINTER_KEY_CONTEXT = b"muninn-bundle-pointer-key-v1"

# ── v2 crypto-core: in-band alg + HKDF key separation (bundle_version 2) ──────
#
# ALG_V2 is the in-band scheme identifier the v2 bundle carries (see
# shadow.bundle): "<signature-alg>+<pointer-alg>". It is folded INTO the
# signed bundle, so the signing scheme AND the pointer scheme are both on the
# wire and tamper-evident, and either can be swapped later (PQC-readiness)
# behind a new alg/bundle_version without a forced client redeploy: the server
# dispatches validation/verification on the declared version.
ALG_V2 = "ed25519+hmac-sha256"

# HKDF-SHA256 (RFC 5869) domain separation for v2. THE ROOT SECRET IS THE
# ed25519 PRIVATE SEED (private_bytes_raw(), 32 bytes) that already lives in
# the customer's PEM -- the CI secret MUNINN_CLIENT_PRIVATE_KEY_PEM, set once
# at enrollment and never transmitted (see generate_keypair). Nothing new is
# generated, stored, or rotated separately. A fixed, NON-SECRET salt plus a
# per-purpose info label give each derived key its own domain, so the
# pointer-HMAC key and the signing domain never reuse the same key material.
_HKDF_SALT = b"muninn/crypto-core/v2"
_HKDF_INFO_SIGN = b"muninn/crypto-core/v2/ed25519-sign"
_HKDF_INFO_POINTER = b"muninn/crypto-core/v2/pointer-hmac"


@dataclass(frozen=True)
class Keypair:
    """A freshly generated ed25519 keypair, serialized for storage.

    private_pem is meant to become a repo secret (customer-side, never
    transmitted). public_pem is the thing that eventually gets registered
    with a server. Both are plain PEM bytes so they can be written to a
    file, an env var, or a secrets manager with no further encoding.
    """
    key_id: str
    private_pem: bytes
    public_pem: bytes


def generate_key_id(prefix: str = KEY_ID_PREFIX, version: int = KEY_ID_VERSION) -> str:
    """A new opaque key id, e.g. "cust_3f9a1c2b7e6d0a4f:v1". The opaque part
    is a random token (secrets.token_hex), not derived from any customer
    identifier, so the id itself discloses nothing."""
    return f"{prefix}_{secrets.token_hex(16)}:v{version}"


def generate_keypair(key_id: str = "") -> Keypair:
    """First-run keygen: generate a new ed25519 keypair locally. No network,
    no server, nothing transmitted. If key_id is not given, one is minted
    with generate_key_id()."""
    key_id = key_id or generate_key_id()
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return Keypair(key_id=key_id, private_pem=private_pem, public_pem=public_pem)


def derive_pointer_key(private_pem: bytes) -> bytes:
    """Derive the per-customer bundle-pointer HMAC key (shadow.bundle's
    pointer_key) from the SAME ed25519 private key material this module
    signs with. One customer, one signing key, one deterministically-derived
    pointer key -- nothing new to generate, store, or rotate separately.

    HMAC-SHA256 keyed derivation over the private key's raw 32-byte seed
    (Ed25519PrivateKey.private_bytes_raw(), not a new primitive: hashlib/hmac
    are stdlib), domain-separated from the signing use of this same key by a
    fixed context label (_POINTER_KEY_CONTEXT) so a pointer-key leak can
    never be replayed as a signing key and vice versa, and so this
    derivation can never collide with a different use of the same seed.
    Raises ValueError if private_pem is not a valid PEM-encoded ed25519
    private key -- fail loudly at derive time, not silently later when a
    bundle's pointers turn out to be inconsistent."""
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("private_pem does not decode to an ed25519 private key")
    seed = private_key.private_bytes_raw()
    return hmac.new(seed, _POINTER_KEY_CONTEXT, hashlib.sha256).digest()


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF (extract-then-expand) over SHA-256, stdlib hmac/hashlib
    only -- no new primitive beyond what this module already uses. Extract
    derives a pseudorandom key (PRK) from the input keying material under
    ``salt``; expand stretches the PRK to ``length`` bytes bound to ``info``
    (the per-purpose domain label). Two calls that differ ONLY in ``info``
    produce cryptographically independent outputs -- that is the property v2
    relies on to keep the pointer-HMAC key and the signing domain from ever
    sharing key material."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def _ed25519_seed(private_pem: bytes) -> bytes:
    """The raw 32-byte ed25519 seed behind a PEM private key -- the v2 ROOT
    SECRET all v2 keys are derived from. Raises ValueError if private_pem is
    not a valid ed25519 private key."""
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("private_pem does not decode to an ed25519 private key")
    return private_key.private_bytes_raw()


def derive_bundle_keys_v2(private_pem: bytes) -> Dict[str, bytes]:
    """Derive the v2 domain-separated key set from a customer's ed25519
    private key (the ROOT SECRET -- see the _HKDF_SALT comment). Returns
    {"sign": <32 bytes>, "pointer": <32 bytes>}: two INDEPENDENT HKDF-SHA256
    outputs under distinct info labels (_HKDF_INFO_SIGN vs _HKDF_INFO_POINTER)
    so the pointer-HMAC key and the signing domain never reuse the same key
    material.

    "pointer" is the key shadow.bundle tokenizes every v2 pointer under.
    "sign" is the HKDF-derived signing-DOMAIN key: v2 still SIGNS the envelope
    with the raw ed25519 private key (so the already-registered public key
    keeps verifying unchanged -- back-compat is mandatory), and this label is
    reserved so a future non-ed25519 alg -- the PQC swap the in-band ALG_V2
    field exists to enable -- can adopt an HKDF-derived signing key without
    ever colliding with the pointer domain. Raises ValueError if private_pem
    is not a valid ed25519 private key."""
    seed = _ed25519_seed(private_pem)
    return {
        "sign": _hkdf_sha256(seed, _HKDF_SALT, _HKDF_INFO_SIGN, 32),
        "pointer": _hkdf_sha256(seed, _HKDF_SALT, _HKDF_INFO_POINTER, 32),
    }


def derive_pointer_key_v2(private_pem: bytes) -> bytes:
    """The v2 per-customer bundle-pointer HMAC key: the "pointer" half of
    derive_bundle_keys_v2 (HKDF-SHA256 of the ed25519 seed under the
    pointer-domain info label). Replaces v1's single plain HMAC derivation
    (derive_pointer_key) with a full extract-and-expand plus domain
    separation. v1 is kept UNCHANGED so already-deployed clients still
    reproduce identical pointers. Raises ValueError on a non-ed25519 PEM."""
    return derive_bundle_keys_v2(private_pem)["pointer"]


class CanonicalizationError(ValueError):
    """Raised when a bundle (or signed payload) cannot be canonicalized into
    strict, round-trip-safe JSON: it contains a NaN/Infinity float (which
    json.dumps permits under its default allow_nan=True but which is not
    valid JSON and would not survive a strict server-side parser
    identically), or the canonical bytes do not reparse to equivalent data.
    A caller must never catch and silently ignore this -- signing/verifying
    a value that cannot be canonicalized the same way twice is exactly the
    ambiguity docs/protocol-spec.md's frozen canonicalization rules exist to
    rule out."""


def _canonical_bundle_bytes(bundle: Dict[str, Any]) -> bytes:
    """Deterministic serialization for signing/verifying: sorted keys, no
    incidental whitespace, ensure_ascii=False, allow_nan=False, same shape
    every time regardless of the dict's in-memory key order. Same
    canonical-JSON shape as shadow/review.py's _canonical_json, reused here
    for signature stability rather than content fingerprinting. The exact
    rules (sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    allow_nan=False) are frozen and documented in docs/protocol-spec.md so a
    server-side re-implementation stays byte-identical.

    allow_nan=False makes json.dumps RAISE (wrapped below as
    CanonicalizationError) instead of silently emitting NaN/Infinity tokens
    that are not valid JSON -- a strict server parser would diverge from
    what the client signed. The canonical bytes are then reparsed and
    compared back against the input as a round-trip check: any value that
    does not survive its own canonical encoding unchanged is rejected rather
    than silently signed."""
    try:
        payload = json.dumps(
            bundle, sort_keys=True, ensure_ascii=False,
            separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    except (ValueError, TypeError) as exc:
        raise CanonicalizationError(
            f"bundle does not canonicalize to strict JSON: {exc}") from exc
    try:
        reparsed = json.loads(payload)
    except ValueError as exc:
        raise CanonicalizationError(
            f"canonical bytes did not round-trip through json.loads: {exc}"
        ) from exc
    if reparsed != bundle:
        raise CanonicalizationError(
            "canonical bytes reparsed to data different from the input; "
            "canonicalization is not round-trip-safe for this bundle")
    return payload


def sign_bundle(bundle: Dict[str, Any], private_pem: bytes, key_id: str, *,
                nonce: Optional[str] = None,
                issued_at: Optional[str] = None) -> Dict[str, Any]:
    """Wrap a Phase 2 bundle (shadow.bundle.assemble_bundle's return value)
    in a detached ed25519 signature envelope. The bundle object itself is
    carried unchanged so it stays human-readable/diffable; only the
    signature block is new.

    ``nonce`` and ``issued_at`` are normally left as None so a fresh random
    nonce (secrets.token_hex(16)) and the current stamp
    (shadow.doctor.resolve_now) are minted for every call -- a caller only
    passes them explicitly to reproduce an exact prior signature (tests) or
    to source ``issued_at`` from the same clock reading the rest of a run
    uses. Both are bound into the signed payload alongside alg/key_id/bundle
    (see module docstring): a server can eventually enforce freshness and a
    nonce cache against them, and an attacker cannot relabel key_id/alg
    without invalidating the signature.

    Raises ValueError if private_pem is not a valid PEM-encoded ed25519
    private key -- a caller signing with the wrong key material should fail
    loudly at sign time, not silently later at verify time. Raises
    CanonicalizationError if the bundle cannot be canonicalized to strict,
    round-trip-safe JSON."""
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("private_pem does not decode to an ed25519 private key")
    nonce = nonce if nonce is not None else secrets.token_hex(NONCE_HEX_LEN // 2)
    issued_at = issued_at if issued_at is not None else resolve_now(None)
    protected_header = {
        "alg": ALG, "key_id": key_id, "nonce": nonce, "issued_at": issued_at,
        "bundle": bundle,
    }
    payload = _canonical_bundle_bytes(protected_header)
    sig = private_key.sign(payload)
    return {
        "bundle": bundle,
        "signature": {
            "alg": ALG,
            "key_id": key_id,
            "nonce": nonce,
            "issued_at": issued_at,
            "sig": base64.b64encode(sig).decode("ascii"),
        },
    }


def verify_envelope(envelope: Dict[str, Any], public_pem: bytes) -> bool:
    """Verify a signed envelope's signature over its protected header
    (alg, key_id, nonce, issued_at, bundle -- see module docstring), against
    the given ed25519 public key. Fail closed: any malformed envelope,
    decoding error, wrong key type, or signature mismatch returns False
    rather than raising. True means, and only means, that the exact
    alg/key_id/nonce/issued_at/bundle combination present in this envelope
    was signed by the holder of the private key matching public_pem -- it
    says nothing about whether public_pem itself belongs to who a caller
    thinks it does, and nothing about freshness (key registration/trust and
    replay/nonce-cache enforcement are a later server phase's problem, not
    this function's)."""
    try:
        bundle = envelope["bundle"]
        signature = envelope["signature"]
        alg = signature.get("alg")
        if alg != ALG:
            return False
        key_id = signature.get("key_id")
        nonce = signature.get("nonce")
        issued_at = signature.get("issued_at")
        if not isinstance(key_id, str) or not isinstance(nonce, str) \
                or not isinstance(issued_at, str):
            return False
        sig_bytes = base64.b64decode(signature["sig"], validate=True)
        public_key = serialization.load_pem_public_key(public_pem)
        if not isinstance(public_key, Ed25519PublicKey):
            return False
        protected_header = {
            "alg": alg, "key_id": key_id, "nonce": nonce,
            "issued_at": issued_at, "bundle": bundle,
        }
        payload = _canonical_bundle_bytes(protected_header)
        public_key.verify(sig_bytes, payload)
        return True
    except Exception:
        # fail closed: a malformed envelope, a bad signature, a tampered
        # bundle, or a wrong key must all read as "not verified", never
        # raise past this boundary.
        return False

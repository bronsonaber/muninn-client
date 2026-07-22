"""shadow/keygen.py: first-run key-provisioning CLI for Phase 6's SERVER
MODE client credential (the design-partner manual loop, the decided
default for this phase -- see PROVISIONING.md for the full
flow this CLI is step 1 of).

WHAT THIS DOES: generates a new ed25519 keypair locally (reusing
shadow.signing.generate_keypair, the exact same keygen Phase 3 already
uses), writes the PRIVATE key straight to a local file, and prints ONLY
the PUBLIC key (PEM) and the key_id to stdout, followed by plain-English
next steps. No network call. No server contacted. Nothing here talks to
shadow.server_client at all.

WHY THE PRIVATE KEY IS NEVER PRINTED: "prints ONLY the public key plus a
key_id" is a hard requirement, not a style choice -- a terminal's stdout is
routinely captured (shell history expansion, CI logs, screen-recording,
copy-paste into a chat window to ask for help). The private key is written
directly to a file instead, with owner-only permissions where the platform
supports it (chmod 0600), so a customer's own operational habits around
"don't paste your terminal output anywhere" are enough to keep it safe.
tests/test_shadow_keygen.py asserts the generated private key's PEM string
is never present in captured stdout, in addition to reading it via the
Keypair this CLI's run() returns for a full round-trip.

THE FLOW THIS CLI KICKS OFF (fully spelled out again in the printed
instructions and in PROVISIONING.md):
  1. Run this CLI once. It writes a private-key PEM file locally and prints
     the public key + key_id.
  2. Register the printed public key + key_id with Muninn. Today that is a
     manual step (send it to be added to the server's key registry) -- there
     is no self-service registration endpoint yet.
  3. Store the private-key file's contents as a repo secret named
     MUNINN_CLIENT_PRIVATE_KEY_PEM (and the key_id as MUNINN_CLIENT_KEY_ID,
     not sensitive), which action.yml's client-private-key /
     client-key-id inputs map into the env shadow.pr_action reads.
  4. Delete the local private-key file once the secret is saved -- it has no
     further purpose on this machine and is plaintext while it exists.

If a customer skips this entirely and just sets MUNINN_SERVER_URL without
ever running this CLI, shadow.pr_action.build_server_receipt() still works
(it falls back to a fresh ephemeral keypair every run), it just always
comes back as "no receipt" because an ephemeral key can never be
registered in advance -- shadow.pr_action.run() now logs a one-line notice
explaining exactly that instead of leaving the failure unexplained (see
this module's own module docstring cross-reference in shadow/pr_action.py).
"""
from __future__ import annotations

import argparse
import pathlib
import stat
import sys
from typing import Optional, Sequence, TextIO

from shadow import signing

DEFAULT_OUT = "muninn_client_key.pem"


def _write_private_key(path: pathlib.Path, private_pem: bytes) -> None:
    """Write the private key PEM to `path` and restrict it to owner
    read/write only (0600) where the platform honors chmod. Never returns
    the bytes anywhere they could end up on stdout."""
    path.write_bytes(private_pem)
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        # Best-effort on platforms/filesystems that don't support chmod
        # (e.g. some Windows filesystems) -- the file still exists and is
        # still never printed; this is a hardening extra, not the control.
        pass


def run(*, out_path: str = DEFAULT_OUT, stdout: Optional[TextIO] = None) -> int:
    """The testable core. Generates a keypair, writes the private key to
    `out_path`, and writes ONLY the public key + key_id + instructions to
    `stdout` (defaults to sys.stdout). Refuses to overwrite an existing
    file at `out_path` rather than silently clobbering a key a customer may
    already have registered."""
    out = stdout or sys.stdout
    path = pathlib.Path(out_path)
    if path.exists():
        out.write(
            f"muninn-keygen: refusing to overwrite existing file '{path}'. "
            "Move or delete it first if you intend to generate a new "
            "key.\n")
        return 1

    kp = signing.generate_keypair()
    _write_private_key(path, kp.private_pem)

    out.write("muninn-keygen: generated a new ed25519 client signing "
             "keypair.\n\n")
    out.write(f"key_id: {kp.key_id}\n\n")
    out.write("public key (PEM) -- safe to share, register this with "
             "Muninn:\n")
    out.write(kp.public_pem.decode("ascii"))
    out.write("\n")
    out.write(
        "The private key is never printed here and is never transmitted "
        f"anywhere; it was written straight to a local file: '{path}'.\n\n"
        "NEXT STEPS:\n"
        "  1. Register this public key: send the key_id and the public "
        "key PEM above to be added to the Muninn server's key registry "
        "(manual step for now -- there is no self-service registration "
        "endpoint yet).\n"
        f"  2. Store the private key as a repo secret: open '{path}', "
        "copy its full contents, and save them as a GitHub Actions secret "
        "named MUNINN_CLIENT_PRIVATE_KEY_PEM on the repo that runs the "
        "Muninn Action (Settings -> Secrets and variables -> Actions -> "
        "New repository secret). Also set the key_id above as "
        "MUNINN_CLIENT_KEY_ID (not sensitive; a secret or a plain repo "
        "variable both work) and wire both into the Action's "
        "client-private-key / client-key-id inputs.\n"
        f"  3. Delete the local file once the secret is saved: '{path}' "
        "is plaintext private key material on this machine and has no "
        "further purpose after step 2.\n")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m shadow.keygen",
        description=("Generate a new ed25519 client signing keypair for "
                     "Muninn server mode. Prints the public key + key_id; "
                     "writes the private key straight to a local file, "
                     "never to stdout."))
    parser.add_argument(
        "--out", default=DEFAULT_OUT,
        help=(f"Path to write the PRIVATE key PEM to (default: "
             f"{DEFAULT_OUT}). Never printed to stdout."))
    args = parser.parse_args(argv)
    return run(out_path=args.out)


if __name__ == "__main__":
    sys.exit(main())
